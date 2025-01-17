#!/bin/bash

set -e

# Debug?
if [ -n "$ZSCAN_DEBUG" ]; then
  set -x
  pwd
  ls -la
fi

# Define mandatory parameters
server_url=${ZSCAN_SERVER_URL:-https://zc202.zimperium.com}
client_id=${ZSCAN_CLIENT_ID:-}
secret=${ZSCAN_CLIENT_SECRET:-}
team_name=${ZSCAN_TEAM_NAME:-Default}
input_file=${ZSCAN_INPUT_FILE:-$1}
report_format=${ZSCAN_REPORT_FORMAT:-sarif}

# Optional parameters
report_location=${ZSCAN_REPORT_LOCATION:-.}
report_file_name=${ZSCAN_REPORT_FILE_NAME:-}
wait_for_report=${ZSCAN_WAIT_FOR_REPORT:-true}
wait_interval=${ZSCAN_POLLING_INTERVAL:-30}
branch_name=${ZSCAN_BRANCH:-}
build_number=${ZSCAN_BUILD_NUMBER:-}
environment=${ZSCAN_ENVIRONMENT:-}

# drone plugin output file
# this will contain the filename of the report
# leave default unless you know what you're doing
drone_output=${PLUGIN_DRONE_OUTPUT:-DRONE_OUTPUT.env}

# internal constants
login_url="/api/auth/v1/api_keys/login"
upload_url="/api/zdev-upload/public/v1/uploads/build"
status_url="/api/zdev-app/public/v1/assessments/status?buildId="
teams_url="/api/auth/public/v1/teams"
complete_upload_url="/api/zdev-app/public/v1/apps"
download_assessment_url="/api/zdev-app/public/v1/assessments"

AssessmentID=""
ScanStatus="Submitted"
ciToolId="GTLB"
ciToolName="GitLab Pipeline"

# Input Validation
# Input file must be specified
if [ -z "$input_file" ]; then
  echo "Error: Please provide the path to the APK/IPA file in the plugin settings or as a command-line argument."
  exit 1
fi

# Input file must exist
if ! [ -f "$input_file" ]; then
  echo "Error: File "$input_file" does not exist."
  exit 1
fi

# Credentials must be specified
if [ -z "$client_id" ] || [ -z "$secret" ]; then
  echo "Error: Please provide client id and secret via environment variables. Refer to the documentation for details."
  exit 1
fi

# Output format must be one of [json, sarif]
if [ "$report_format" != "json" ] && [ "$report_format" != "sarif" ]; then
  echo "Error: Output format must be one of [json, sarif]."
  exit 1
fi

# Minimum wait time is 30 seconds; we don't want to DDOS our own servers
if [ $wait_interval -lt 30 ]; then
  wait_interval=30
fi

# Remove trailing spaces
server_url="${server_url%% *}"
# Remove trailing slashes from the URL
server_url="${server_url%%/*}"
echo "Using console at '${server_url}'."

# Execute the curl command with the server URL
response=$(curl --location --request POST "${server_url}${login_url}" \
--header 'Content-Type: application/json' \
--data-raw "{ \"clientId\": \"$client_id\", \"secret\": \"${secret}\" }" 2>/dev/null)

# Check if the curl command was successful (exit code 0)
if [[ $? -eq 0 ]]; then
  # Use jq (assuming it's installed) to parse JSON and extract accessToken
  access_token=$(echo "$response" | jq -r '.accessToken')

  # Check if access token is found
  if [[ -n "$access_token" ]]; then
    # If debug set, print the token.  Otherwise, print the first 10 characters.
    if [ -n "$ZSCAN_DEBUG" ]; then
      echo "Extracted access token: ${access_token}"
    else
      echo "Extracted access token: ${access_token:0:10}..."
    fi
  else
    echo "Error: access token not found in response."
  fi
else
  echo "Error: unable to obtain access token."
  exit 3
fi

# Construct the Authorization header with Bearer token
AUTH_HEADER="Authorization: Bearer ${access_token}"

response=$(curl -X POST \
  -H "${AUTH_HEADER}" \
  -H "Content-Type: multipart/form-data" \
  -F "buildFile=@${input_file}" \
  -F "buildNumber=${build_number}" \
  -F "environment=${environment}" \
  -F "branchName=${branch_name}" \
  -F "ciToolId=${ciToolId}" \
  -F "ciToolName=${ciToolName}" \
  "${server_url}${upload_url}" 2>/dev/null)

# Check for successful response (status code 200)
if [ $? -eq 0 ]; then
  # Convert JSON response to a readable format
  formatted_json=$(echo "$response" | jq .)

  # Extract buildId and buildUploadedAt using jq
  zdevAppId=$(echo "$formatted_json" | jq -r '.zdevAppId')
  buildId=$(echo "$formatted_json" | jq -r '.buildId')
  buildUploadedAt=$(echo "$formatted_json" | jq -r '.buildUploadedAt')
  appBuildVersion=$(echo "$formatted_json" | jq -r '.zdevUploadResponse.appBuildVersion')
  uploadedBy=$(echo "$formatted_json" | jq -r '.uploadMetadata.uploadedBy')
  bundleIdentifier=$(echo "$formatted_json" | jq -r '.zdevUploadResponse.bundleIdentifier')
  appVersion=$(echo "$formatted_json" | jq -r '.zdevUploadResponse.appVersion')  

  # Check if variables were extracted successfully
  if [ -z "$buildId" ] || [ -z "$buildUploadedAt" ] || [ -z "$appBuildVersion" ] || [ -z "$bundleIdentifier" ] || [ -z "$appVersion" ]; then
    echo "Error: Failed to extract buildId or buildUploadedAt from response."
  else
    echo "Successfully uploaded Binary: ${INPUT}"
    echo "buildId: $buildId"
    echo "buildUploadedAt: $buildUploadedAt"
    echo "buildNumber (appBuildVersion): $appBuildVersion"
    echo "bundleIdentifier: $bundleIdentifier"
    echo "appVersion: $appVersion"
  fi
else
  echo "Error: Failed to upload APK file."
  echo "Response code: $?"
fi

# Assign to a team if this is a new application - teamId is null
teamId=$(echo "$formatted_json" | jq -r '.teamId')
if [ "$teamId" == "null" ]; then
  echo "Assigning the application to team $team_name."

  # Fetch the list of teams using the access token
  teams_response=$(curl --location --request GET "${server_url}${teams_url}" \
    --header "Authorization: Bearer ${access_token}" 2>/dev/null)

  if [[ $? -eq 0 ]]; then
    teams_json=$(echo "$teams_response" | jq .)

    teamId=$(echo "$teams_json" | jq -r --arg team_name "$team_name" '.content[] | select(.name==$team_name) | .id')

    if [ -z "$teamId" ]; then
      echo "Error: Failed to extract teamId for the team named '$team_name'. Please ensure you have granted the Authorization token the 'view teams' permission under the 'Common' category, within the console's Authorization settings."
      exit 1
    else
      echo -e "\nSuccessfully extracted teamId: '$teamId' for Team named: '$team_name'."

      # Perform the second API call to complete the upload
      second_response=$(curl --location --request PUT "${server_url}${complete_upload_url}/${zdevAppId}/upload" \
        --header "Content-Type: application/json" \
        --header "${AUTH_HEADER}" \
        --data "{
          \"teamId\": \"${teamId}\",
          \"buildNumber\": \"${appBuildVersion}\"
        }" 2>/dev/null)

      if [[ $? != 0 ]]; then
        echo "Error: Failed to perform assign the application to the specified team. Although the scan will complete, the results will not be visible in the console UI. Set Debug to 1 to troubleshoot."
      fi
    fi
  else
    echo "Error: Failed to extract the list of teams from your console. Although the scan will complete, the results will not be visible in the console UI. Please ensure you have granted the Authorization token the 'view teams' permission under the 'Common' category, within the console's Authorization settings."
  fi  
fi

# If no need to wait for report, we're done
if [ "$wait_for_report" != "true" ]; then
  echo "ZSCAN_WAIT_FOR_REPORT is not set. We're done!"
  exit 0
fi

# Check the Status in a loop - wait for Interval
# TODO: add timeout
while true; do 
  # Check the Status
  response=$(curl -X GET \
    -H "${AUTH_HEADER}" \
    -H "Content-Type: application/json" \
    "${server_url}${status_url}${buildId}" 2>/dev/null)

  sleep 5 
  formatted_json=$(echo "$response" | jq .)

  if [ $? -eq 0 ]; then
    ScanStatus=$(echo "$formatted_json" | jq -r '.zdevMetadata.analysis')

    if [[ ${ScanStatus} == "Done" ]]; then
      AssessmentID=$(echo "$formatted_json" | jq -r '.id')
      echo "Scan ${AssessmentID} is Done."
      break # Exit the loop
    else 
      echo "Scan is not completed. Status: ${ScanStatus}."
    fi
  else
    echo "Error Checking the Status of Scan."
  fi  
  # Sleep for the interval
  sleep ${wait_interval}
done


# Retrieve the report
# Figure out report's fully qualified file name
# if not explicitly set, use the default
if [ -z $report_file_name ]; then
  OUTPUT_FILE=$report_location/zscan-results-${AssessmentID}-${report_format}.json
else
  OUTPUT_FILE=$report_location/$report_file_name
fi

# Send GET request with curl and capture the response
curl -s -o "${OUTPUT_FILE}" -H "${AUTH_HEADER}" "${server_url}${download_assessment_url}/${AssessmentID}/${report_format}"

# Check for errors in the curl command
if [ $? -ne 0 ]; then
  echo "Error: curl command failed."
  exit 1
fi

# Print confirmation message
echo "Response saved to: $OUTPUT_FILE"

# write out the name of the output file to be used in subsequent steps or stages
echo "ZSCAN_OUTPUT_FILE=$OUTPUT_FILE" >> $drone_output

if [ -n "$ZSCAN_DEBUG" ]; then
  ls -la
fi
