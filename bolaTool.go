package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// represents a single entry in log file
type LogData struct {
	Req struct {
		Path       string `json:"url"`
		Query      string `json:"qs_params"`
		Headers    string `json:"headers"`
		BodyLength int    `json:"req_body_len"`
	} `json:"req"`
	Rsp struct {
		StatusCodeGroup string `json:"status_class"`
		BodySize        int    `json:"rsp_body_len"`
	} `json:"rsp"`
}

// pulls out the user token from headers using "Bearer" to find a regex match
func extractToken(headers string) string {
	pattern := regexp.MustCompile(`Authorization:\s*Bearer\s*([\w-]+)`)
	matches := pattern.FindStringSubmatch(headers)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// pulls out the user ID from the query string in the URL
func extractIDFromURL(url string) string {
	pattern := regexp.MustCompile(`user_id=(\d+)`)
	matches := pattern.FindStringSubmatch(url)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// analyzeLogFile scans the access log file for suspicious behavior
func analyzeLogFile(logFilePath string) {
	file, err := os.Open(logFilePath)
	if err != nil {
		fmt.Printf("Error: Unable to open file in path %s - %v\n", logFilePath, err)
		return
	}
	defer file.Close()

	userResourceAccess := make(map[string]map[string]bool)
	var suspiciousLogs []string

	//read file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry LogData
		err := json.Unmarshal([]byte(line), &entry)
		if err != nil {
			fmt.Printf("Error parsing log entry: %v\n", err)
			continue
		}

		userToken := extractToken(entry.Req.Headers)
		resourceID := extractIDFromURL(entry.Req.Path)

		if userToken == "" || resourceID == "" {
			continue
		}

		_, exists := userResourceAccess[userToken]
		if !exists {
			userResourceAccess[userToken] = make(map[string]bool)
		}

		//detecs whether the user searched for another userID but his
		if !userResourceAccess[userToken][resourceID] {
			//if the inner map has one or more entries, it's likely that
			//the user is trying to reach a resource that isn't his
			if len(userResourceAccess[userToken]) > 0 {
				suspiciousLogs = append(suspiciousLogs, line)
			}
			userResourceAccess[userToken][resourceID] = true
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading log file: %v\n", err)
	}

	fmt.Println("Suspicious Access Attempts Detected:")
	for _, log := range suspiciousLogs {
		fmt.Println(log)
	}
}

func main() {
	var logFilePath string
	fmt.Println("Enter the full path of the access log file:")
	fmt.Scanln(&logFilePath)
	analyzeLogFile(logFilePath)
}
