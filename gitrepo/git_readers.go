package gitrepo

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// DefaultMaxBlobSize is the default maximum size, in bytes, of a git object
// that will be loaded into memory while reading from the object database.
// Objects larger than this are not read into memory; they are reported as
// errors instead, so that scanning does not exhaust memory on oversized blobs.
const DefaultMaxBlobSize = 10 * 1024 * 1024 // 10 MB

// ErrBlobTooLarge is returned (wrapped) when a git object is larger than the
// configured maximum blob size and is therefore not read into memory.
var ErrBlobTooLarge = errors.New("blob size exceeds the maximum allowed size")

type ReadFunc func(string) ([]byte, error)
type BatchReader interface {
	Start() error
	Read(string) ([]byte, error)
	Shutdown() error
}

type BatchGitObjectReader struct {
	repo         *GitRepo
	cmd          *exec.Cmd
	inputWriter  *bufio.Writer
	outputReader *bufio.Reader
	read         ReadFunc
	maxBlobSize  int
}

func (bgor *BatchGitObjectReader) Start() error {
	return bgor.cmd.Start()
}

func (bgor *BatchGitObjectReader) Shutdown() error {
	return bgor.cmd.Process.Kill()
}

func (bgor *BatchGitObjectReader) Read(expr string) ([]byte, error) {
	return bgor.read(expr)
}

func newBatchGitObjectReader(root string, maxBlobSize int) *BatchGitObjectReader {
	repo := &GitRepo{root}
	cmd := repo.makeRepoCommand("git", "cat-file", "--batch=%(objectsize)")
	inputPipe, err := cmd.StdinPipe()
	if err != nil {
		logrus.Fatalf("error creating stdin pipe for batch git file reader subprocess: %v", err)
	}
	outputPipe, err := cmd.StdoutPipe()
	if err != nil {
		logrus.Fatalf("error creating stdout pipe for batch git file reader subprocess: %v", err)
	}
	batchReader := BatchGitObjectReader{
		repo:         repo,
		cmd:          cmd,
		inputWriter:  bufio.NewWriter(inputPipe),
		outputReader: bufio.NewReader(outputPipe),
		maxBlobSize:  maxBlobSize,
	}
	return &batchReader
}

func NewBatchGitHeadPathReader(root string) BatchReader {
	bgor := newBatchGitObjectReader(root, DefaultMaxBlobSize)
	bgor.read = bgor.makePathReader(GIT_HEAD_PREFIX)
	return bgor
}

func NewBatchGitStagedPathReader(root string) BatchReader {
	bgor := newBatchGitObjectReader(root, DefaultMaxBlobSize)
	bgor.read = bgor.makePathReader(GIT_STAGED_PREFIX)
	return bgor
}

func NewBatchGitObjectHashReader(root string) BatchReader {
	bgor := newBatchGitObjectReader(root, DefaultMaxBlobSize)
	bgor.read = bgor.makeObjectHashReader()
	return bgor
}

type gitCatFileReadResult struct {
	contents []byte
	err      error
}

func (bgor *BatchGitObjectReader) makePathReader(prefix string) ReadFunc {
	pathChan := make(chan ([]byte))
	resultsChan := make(chan (gitCatFileReadResult))
	go bgor.doCatFile(pathChan, resultsChan)
	return func(path string) ([]byte, error) {
		pathChan <- []byte(prefix + ":" + path)
		result := <-resultsChan
		return result.contents, result.err
	}
}

func (bgor *BatchGitObjectReader) makeObjectHashReader() ReadFunc {
	objectHashChan := make(chan ([]byte))
	resultsChan := make(chan (gitCatFileReadResult))
	go bgor.doCatFile(objectHashChan, resultsChan)
	return func(objectHash string) ([]byte, error) {
		objectHashChan <- []byte(objectHash)
		result := <-resultsChan
		return result.contents, result.err
	}
}

func (bgor *BatchGitObjectReader) doCatFile(gitExpressionChan chan ([]byte), resultsChan chan (gitCatFileReadResult)) {
	for {
		gitExpression := <-gitExpressionChan
		gitExpression = append(gitExpression, '\n')
		//Write file-path expression to process input
		bgor.inputWriter.Write(gitExpression)
		bgor.inputWriter.Flush()

		//Read line containing filesize from process output.
		//ReadSlice (instead of ReadBytes) bounds the memory used for the
		//header: a malformed or desynchronised stream containing very long
		//lines is reported as an error instead of being buffered in full.
		filesizeBytes, err := bgor.outputReader.ReadSlice('\n')
		if err != nil {
			if err == bufio.ErrBufferFull {
				err = fmt.Errorf("object size header for %s is longer than the read buffer", strings.TrimSpace(string(gitExpression)))
			}
			logrus.Errorf("error reading filesize: %v", err)
			resultsChan <- gitCatFileReadResult{[]byte{}, err}
			continue
		}
		filesize, err := strconv.Atoi(string(filesizeBytes[:len(filesizeBytes)-1]))
		if err != nil {
			logrus.Errorf("error parsing filesize: %v", err)
			resultsChan <- gitCatFileReadResult{[]byte{}, err}
			continue
		}
		if filesize < 0 {
			err := fmt.Errorf("invalid object size %d reported for %s", filesize, strings.TrimSpace(string(gitExpression)))
			logrus.Errorf("%v", err)
			resultsChan <- gitCatFileReadResult{[]byte{}, err}
			continue
		}
		logrus.Debugf("Git Batch Reader: FilePath: %v, Size:%v", gitExpression, filesize)

		//Enforce the memory budget before allocating anything for the blob:
		//oversized objects are drained from the stream (to keep the batch
		//protocol in sync) but are never held in memory.
		if filesize > bgor.maxBlobSize {
			if err := bgor.discardObjectContents(filesize); err != nil {
				logrus.Errorf("error discarding oversized object contents: %v", err)
				resultsChan <- gitCatFileReadResult{[]byte{}, err}
				continue
			}
			err := fmt.Errorf("%w: %s is %d bytes, larger than the maximum of %d bytes", ErrBlobTooLarge, strings.TrimSpace(string(gitExpression)), filesize, bgor.maxBlobSize)
			logrus.Errorf("%v", err)
			resultsChan <- gitCatFileReadResult{[]byte{}, err}
			continue
		}

		//Read file contents upto filesize bytes from process output
		fileBytes := make([]byte, filesize)
		n, err := io.ReadFull(bgor.outputReader, fileBytes)
		if n != filesize || err != nil {
			logrus.Errorf("error reading exactly %v bytes of %v: %v (read %v bytes)", filesize, gitExpression, err, n)
			resultsChan <- gitCatFileReadResult{[]byte{}, err}
			continue
		}

		//Read and discard trailing newline (not doing this will cause errors going forward)
		b, err := bgor.outputReader.ReadByte()
		if err != nil || b != '\n' {
			resultsChan <- gitCatFileReadResult{[]byte{}, fmt.Errorf("error discarding trailing newline : %v trailing byte: %v", err, b)}
			continue
		}

		resultsChan <- gitCatFileReadResult{fileBytes, nil}
	}
}

// discardObjectContents reads and discards the contents of a git object
// (including its trailing newline) from the batch process output, so that
// oversized objects do not desynchronise the stream for subsequent reads.
func (bgor *BatchGitObjectReader) discardObjectContents(filesize int) error {
	if _, err := io.CopyN(io.Discard, bgor.outputReader, int64(filesize)); err != nil {
		return fmt.Errorf("error discarding %d bytes of oversized object: %v", filesize, err)
	}
	//Read and discard trailing newline (not doing this will cause errors going forward)
	b, err := bgor.outputReader.ReadByte()
	if err != nil || b != '\n' {
		return fmt.Errorf("error discarding trailing newline : %v trailing byte: %v", err, b)
	}
	return nil
}
