#!/bin/bash

logfile="/var/log/apache/access.log"  # Specify the path to your log file here

# Function to parse log file and extract relevant information
parse_log_file() {
    echo "Parsing log file: $logfile"
    
    # Read each line of the log file
    while IFS= read -r line
    do
        # Extract the desired fields from the log line
        ip_address=$(echo "$line" | awk '{print $1}')
        timestamp=$(echo "$line" | awk '{print $4}' | sed 's/\[//')
        request=$(echo "$line" | awk '{print $7}')
        status=$(echo "$line" | awk '{print $9}')
        
        # Display the extracted information
        echo "IP: $ip_address, Timestamp: $timestamp, Request: $request, Status: $status"
        
        # Add your own logic here to further process or analyze the extracted information
    done < "$logfile"
}

# Main function
main() {
    if [ -f "$logfile" ]; then
        parse_log_file
    else
        echo "Log file not found: $logfile"
    fi
}

# Execute the main function
main
