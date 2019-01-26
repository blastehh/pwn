package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/terminal"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	var fileArg string
	flag.StringVar(&fileArg, "f", "", "Optional path to a line separated password file.")
	flag.Parse()
	unknownArgs := flag.Args()
	if len(unknownArgs) > 0 {
		fileArg = unknownArgs[0]
	}
	if fileArg != "" {
		fileName := filepath.Base(fileArg)
		extName := filepath.Ext(fileArg)
		baseName := fileName[:len(fileName)-len(extName)]
		exPath := filepath.Dir(fileArg)
		savePath := exPath + "/" + baseName + "-pwnresult-" + time.Now().Format("20060102-150405") + ".txt"
		savePath = filepath.FromSlash(savePath)

		f, err := os.Open(fileArg)
		check(err)
		defer f.Close()

		outF, err := os.Create(savePath)
		check(err)
		defer outF.Close()

		fmt.Printf("Saving results to: %s\n", savePath)

		fileWriter := bufio.NewWriter(outF)
		fileReader := bufio.NewReader(f)
		counter := 0
		errorCounter := 0
		for {
			passValue, readErr := fileReader.ReadString('\n')
			if readErr != io.EOF {
				check(readErr)
			}

			passValue = strings.TrimRight(passValue, "\r\n")
			if passValue == "" {
				// skip blank lines
				continue
			}

			passHash := getHash(passValue)
			passHashPrefix := passHash[:5]
			list, err := getResults(passHashPrefix)
			if err != nil {
				errorCounter++
				_, werr := fileWriter.WriteString(fmt.Sprintf("%s:error\n", passValue))
				fileWriter.Flush()
				check(werr)
				continue
			}
			_, count := matchHash(passHash, list)
			_, err = fileWriter.WriteString(fmt.Sprintf("%s:%d\n", passValue, count))
			if err != nil {
				fileWriter.Flush()
				panic(err)
			}
			counter++

			if readErr == io.EOF {
				break
			}
			if (counter % 10) == 0 {
				fileWriter.Flush()
			}
		}
		fmt.Printf("%d passwords checked.\n%d errors.", counter, errorCounter)
		fileWriter.Flush()
	} else {
		fmt.Printf("Password checker using api.pwnedpasswords.com\n")
		for {
			passValue := checkPass()
			passHash := getHash(passValue)
			passHashPrefix := passHash[:5]
			list, err := getResults(passHashPrefix)
			if err != nil {
				fmt.Printf("Error retrieving results!\n %s\n\n", err)
				continue
			}
			found, count := matchHash(passHash, list)
			if found {
				fmt.Printf("Password found %d times!\n\n", count)
			} else {
				fmt.Printf("Password not found, you are safe.\n\n")
			}
		}
	}

}

// checkPass prompts for the password to be checked and then returns the string.
func checkPass() string {
	fmt.Printf("Enter a password to check: ")
	pass, _ := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return string(pass)
}

// getHash accepts a string input and returns the sha-1 hash.
func getHash(passInput string) string {
	h := sha1.New()
	h.Write([]byte(passInput))
	sha1Hash := hex.EncodeToString(h.Sum(nil))
	return sha1Hash
}

// getResults accepts the first 5 characters of the hash and queries the API.
// The response is returned.
func getResults(hashPrefix string) (string, error) {
	url := "https://api.pwnedpasswords.com/range/" + hashPrefix
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// matchHash accepts the full password hash and the hash list returned
// from the API, and then makes a comparison.
// Returns true on a match, false on no matches.
// A second return value is provided with the number of matches.
func matchHash(hash string, list string) (bool, int) {
	scanner := bufio.NewScanner(strings.NewReader(list))
	upperHash := (strings.ToUpper(hash))[5:]
	for scanner.Scan() {
		curLine := strings.Split(scanner.Text(), ":")
		curHash, curCount := curLine[0], curLine[1]
		if strings.Compare(upperHash, curHash) == 0 {
			returnCount, _ := strconv.Atoi(curCount)
			return true, returnCount
		}
	}
	return false, 0
}
