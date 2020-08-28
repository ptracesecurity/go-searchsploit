//
// searchsploit.go: This program allows you to search exploits on Shodan using
//  the Shodan API (https://developer.shodan.io/api/exploits/rest).
//
// Gianni Gnesa (@GianniGnesa)
// https://www.ptrace-security.com
//
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

const (
	API_KEY = "{YOUR_API_KEY}"
)

type ShodanResults struct {
	Matches []Exploit `json:"matches"` // Results of the Shodan search
	Total   int       `json:"total"`   // Total number of results
}

type Exploit struct {
	Source      string        `json:"source"`      // Data source (e.g. "CVE")
	ID          interface{}   `json:"_id"`         // Unique ID for the exploit
	Description string        `json:"description"` // The description of the exploit
	OSVDB       []interface{} `json:"osvdb"`       // An array of OSVDB IDs
	BID         []int         `json:"bid"`         // An array of Bugtraq IDs
	CVE         []string      `json:"cve"`         // An array of relevant CVE IDs
	MSB         []string      `json:"msb"`         // An array of Microsoft Security Bulletin reference IDs
	Author      interface{}   `json:"author"`      // The author of the exploit
	Code        string        `json:"code"`        // The actual code of the exploit
	Date        string        `json:"date"`        // The release date of the exploit
	Platform    interface{}   `json:"platform"`    // An array of platforms that the exploit targets
	Port        int           `json:"port"`        // The port number for the affected service
	Type        string        `json:"type"`        // The type of exploit (e.g.)
	Privileged  bool          `json:"privileged"`  // Is Privileged?
	Rank        string        `json:"rank"`        // Rank, i.e. "excellent"
	Version     string        `json:"version"`     // Version
}

func searchExploits(query string) ShodanResults {
	var results ShodanResults
	url := "https://exploits.shodan.io/api/search?query=" + query + "&key=" + API_KEY

	fmt.Println("Calling REST API.")
	resp, err := http.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "searchsploit: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Parsing Response.")
	b, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "searchsploit: reading %s: %v\n", url, err)
		os.Exit(1)
	}
	// fmt.Printf("%s", b)

	fmt.Println("Decoding Results.")
	err = json.Unmarshal(b, &results)
	if err != nil {
		fmt.Println("error:", err)
	}

	return results
}

func main() {

	if len(os.Args) != 2 {
		fmt.Printf("  Usage: %s <query>\n", os.Args[0])
		fmt.Printf("Example: %s <query>\n", os.Args[0])
		os.Exit(1)
	}

	results := searchExploits(os.Args[1])

	fmt.Printf("%+v", results)
}
