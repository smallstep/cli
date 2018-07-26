/*
 * ZCrypto Copyright 2017 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

// ZIntermediate is a command line utility for verifying a set prospective
// intermediate certificates against a root store. Given a set of root
// certificates in PEM format, it can then read in a list of candidate
// intermediates. Candidate certificates are verified against the root store,
// and can optionally chain through any other candidate. All candidate
// certificates will be stored in memory during validation.
//
// ZIntermediate returns any candidate certificate with a chain back to the root
// store, and ignores date-related errors and extended key usage flags, meaning
// ZIntermediate will return both expired intermediates and code-signing
// certificates.
//
// While the candidate certificates can be any certificate, ZIntermediate
// expects they will be intermediates. If a non-intermediate certificate (e.g. a
// certificate without IsCA set to true) is input, ZIntermediate will not build
// chains through it, but will output it as valid.
//
// Examples:
// 	$ zintermediate --roots roots.pem candidates.csv > intermediates.pem
//
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/zmap/zcrypto/x509"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("")

var inputFormatArg string

type inputFormatType int

const (
	inputFormatBase64 inputFormatType = iota
	inputFormatPEM
	inputFormatJSON
)

var inputFormat inputFormatType
var inputFileName, rootFileName string

func init() {
	flag.StringVar(&inputFormatArg, "format", "base64", "One of {base64, pem, json}")
	flag.StringVar(&rootFileName, "roots", "roots.pem", "Path to root store")
	flag.Parse()

	if flag.NArg() < 1 {
		log.Fatalf("missing filename")
	}
	inputFileName = flag.Arg(0)

	inputFormatArg = strings.ToLower(inputFormatArg)
	switch inputFormatArg {
	case "base64":
		inputFormat = inputFormatBase64
	case "pem":
		inputFormat = inputFormatPEM
	case "json":
		inputFormat = inputFormatJSON
	default:
		log.Fatalf("unknown argument for --format \"%s\", see --help", inputFormatArg)
	}
}

func loadPEMPool(r io.Reader) (*x509.CertPool, error) {
	out := x509.NewCertPool()
	scanner := bufio.NewScanner(r)

	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		block, rest := pem.Decode(data)
		if block != nil {
			size := len(data) - len(rest)
			return size, data[:size], nil
		}
		return 0, nil, nil
	})

	for scanner.Scan() {
		pemBytes := scanner.Bytes()
		ok := out.AppendCertsFromPEM(pemBytes)
		if !ok {
			log.Errorf("could not load PEM: %s", scanner.Text())
			return nil, errors.New("unable to load PEM")
		}
	}
	return out, nil
}

func loadBase64Pool(r io.Reader) (*x509.CertPool, error) {
	out := x509.NewCertPool()
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		raw, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			log.Errorf("could not read base64: %s", line)
			return nil, err
		}
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			log.Errorf("could not read certificate %s: %s", line, err)
			continue
		}
		out.AddCert(c)
	}
	return out, nil
}

func main() {
	log.Infof("loading roots from %s", rootFileName)
	rootFile, err := os.Open(rootFileName)
	if err != nil {
		log.Fatalf("could not open %s: %s", rootFileName, err)
	}
	rootPool, err := loadPEMPool(rootFile)
	rootFile.Close()
	if err != nil {
		log.Fatalf("could not load roots: %s", err)
	}

	log.Infof("loading candidate intermediates from %s", inputFileName)
	intermediateFile, err := os.Open(inputFileName)
	if err != nil {
		log.Fatalf("could not open %s: %s", inputFileName, err)
	}
	log.Infof("using input format type %s", inputFormatArg)
	var candidatePool *x509.CertPool
	switch inputFormat {
	case inputFormatPEM:
		candidatePool, err = loadPEMPool(intermediateFile)
	case inputFormatBase64:
		candidatePool, err = loadBase64Pool(intermediateFile)
	default:
		err = fmt.Errorf("unimplemented input type: %s", inputFormatArg)
	}
	intermediateFile.Close()

	if err != nil {
		log.Fatalf("could not load candidate intermediates: %s", err)
	}
	candidates := candidatePool.Certificates()
	log.Infof("loaded %d candidates", len(candidates))

	now := time.Now()
	verifyOpts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: candidatePool,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	log.Infof("validating candidates")
	intermediates := make([]*x509.Certificate, 0)
	rejected := 0
	for idx, candidate := range candidates {
		if idx > 0 {
			log.Infof("checked %d candidates", idx)
		}
		if current, expired, never, _ := candidate.Verify(verifyOpts); len(current) > 0 || len(expired) > 0 || len(never) > 0 {
			intermediates = append(intermediates, candidate)
			continue
		}
		rejected++
	}
	log.Infof("validation complete")
	log.Infof("found %d intermediates", len(intermediates))
	log.Infof("rejected %d candidates", rejected)

	log.Infof("outputing intermediates")
	for _, c := range intermediates {
		block := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}
		pem.Encode(os.Stdout, &block)
	}
	log.Infof("complete")
}
