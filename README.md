# zscan-plugin-gitlab

## GitLab Job script for uploads to zScan

This script can be used to upload mobile applications to Zimperium (zScan) to be scanned for vulnerabilities. Using this script simplifies integrating mobile application security testing into CI/CD process and enables detection and remediation of vulnerabilities earlier in the application SDLC.

For more information on zScan, please see [Continuous Mobile Application Security Scanning](https://www.zimperium.com/zscan/).

## Prerequisites

1. Build environment, e.g., build agent, with `bash` or a compatible shell, `curl`, and `jq`.  Depending on the way this script is integrated into the build pipeline, `wget` and `unzip` may also be needed.
2. Zimperium [MAPS](https://www.zimperium.com/mobile-app-protection/) license that includes zScan functionality.
3. A valid application binary (.ipa, .apk, etc.), either built by the current pipeline or otherwise accessible by the script.
4. API credentials with permissions to upload binaries. In your console, head over to the Authorizations tab in the Account Management section and generate a new API key. At a minimum, the following permissions are required:

- Common Section: Teams - Manage
- zScan Section: zScan Apps - Manage, zScan Assessments - View, zScan Builds - Upload

## Parameters

We recommend using GitLab [Variables](https://docs.gitlab.com/ee/ci/variables/#define-a-cicd-variable-in-the-ui) to provide parameters to the script.  Select [Masked](https://docs.gitlab.com/ee/ci/variables/#mask-a-cicd-variable) or [Masked and hidden](https://docs.gitlab.com/ee/ci/variables/#hide-a-cicd-variable) under Visibility, as needed.  Please refer to the [GitLab Documentation](https://docs.gitlab.com/ee/ci/variables/) for other ways to supply parameters to the script.

### Mandatory

These parameters are mandatory, _unless_ a default value is available as described below.

- **ZSCAN_SERVER_URL**: console base URL, e.g., `https://ziap.zimperium.com/`.
- **ZSCAN_CLIENT_ID** and **ZSCAN_CLIENT_SECRET**: API credentials that can be obtained from the console (see the [Prerequisites](#prerequisites) section above).
- **ZSCAN_INPUT_PATTERN**: the path to the binary or binaries relative to the current workspace.  Either exact filename or a wildcard is accepted. The script will _not_ look inside sub-folders.  No more than 5 files can match the pattern; if the pattern matches more than 5 files, you will need to narrow it down. This is done to minimize the possibility of including too many files by accident, e.g., by specifying `*.*`.  Please remember to enclose _patterns_ in quotes.  Single file path can be used with or without quotes.
- **ZSCAN_TEAM_NAME**: name of the team to which this application belongs.  This is required only if submitting the application for the first time; values are ignored if the application already exists in the console and assigned to a team.  If not supplied, the application will be assigned to the 'Default' team
- **ZSCAN_REPORT_FORMAT**: the format of the scan report, either 'json' or 'sarif' (default).  If you plan on importing zScan results into GitLab Ultimate edition, please use sarif format.  For more information on the SARIF format, please see [OASIS Open](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).

### Optional

These parameters are optional, but may be used to supply additional information about the build and/or control the plugin's output.

- **ZSCAN_REPORT_LOCATION**: destination folder for the vulnerability report. If not provided, the report is stored in the current workspace. Report location and name are important for [Job Artifact](https://docs.gitlab.com/ee/ci/jobs/job_artifacts.html) collection.
- **ZSCAN_REPORT_FILE_NAME**: filename of the report. If not provided, the filename will be patterned as follows: zscan-results-\<AssessmentID\>-\<report-format\>.json, e.g., _zscan-results-123456789-sarif.json_.  **Note:** The filename will be used as-is, so if a pattern that matches multiple input file is provided, only _the last report_ will be preserved.
- **ZSCAN_WAIT_FOR_REPORT**: if set to "true" (default), the script will wait for the assessment report to be complete. Otherwise, the script will exit after uploading the binary to zScan.  The assessment report can be obtained through the console. Report filename and location parameters are ignored. No artifact will be produced.
- **ZSCAN_POLLING_INTERVAL**: wait time for polling the server in seconds. 30 seconds is the default.
- **ZSCAN_BRANCH**: source code branch that the build is based on.
- **ZSCAN_BUILD_NUMBER**: application build number.
- **ZSCAN_ENVIRONMENT**: target environment, e.g., uat, dev, prod.

## Usage

Please refer to [GitLab Documentation](https://docs.gitlab.com/ee/ci/jobs/) for instructions on using scripts in your GitLab pipelines.   In the "Pipeline Editor" section of the Build configuration, add the zScan upload job _after_ the one that builds your application binary, e.g., "assembleDebug".  Here's a _sample_ zScan job that uploads an Android application to zScan and converts zScan SARIF output into GitLab's SAST-compatible artifact:

```yaml
# Upload to zScan and wait for scan results
zScan:
  needs: [assembleDebug]
  interruptible: true
  stage: test
  script:
    - wget -O zScan.tar.gz https://github.com/Zimperium/zscan-plugin-gitlab/archive/refs/tags/v1.0.0.tar.gz
    - tar --strip-components=1 -xf zScan.tar.gz
    - chmod +x zScan.sh
    - ./zScan.sh
    # Optional
    - wget -O sarif-converter https://gitlab.com/ignis-build/sarif-converter/-/releases/v0.9.2/downloads/bin/sarif-converter-linux-amd64
    - chmod +x sarif-converter
    - ./sarif-converter --type sast $ZSCAN_REPORT_FILE_NAME zscan-report.json
  artifacts:
    name: "zScan Results"
    reports:
      sast:
        - zscan-report.json
```

Modify the above script as needed, e.g., replace the tag with the version of your choice.  The sample script assumes that the variables are correctly configured per the [Parameters](#parameters) section above, including server URL, client id/secret, and the input pattern that specifies a pattern that matches a single file.  The optional part uses an open source SARIF-to-GitLab converter to convert zScan report into the format suitable for importing into [GitLab Security dashboard](https://docs.gitlab.com/ee/user/application_security/security_dashboard/).  The Dashboard is only available with the GitLab Ultimate edition.  If dashboard is not available in your installation, omit the optional section and modify the Artifact section of the job to look like this and download the report from the Artifacts tab:

```yaml
  artifacts:
    name: "zScan Results"
    paths:
      $ZSCAN_REPORT_FILE_NAME
```

**Note:** If the script is configured not to wait for an assessment report, no artifacts will be produced.  If the input pattern matches multiple files, the assessment of the _last_ uploaded file will be added as an artifact.  Modify the `artifacts` section to upload multiple assessment reports.

## License

This script is licensed under the MIT License. By using this plugin, you agree to the following terms:

```text
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Enhancements

Submitting improvements to the plugin is welcomed and all pull requests will be approved by Zimperium after review.
