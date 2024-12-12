# zscan-plugin-gitlab

## GitLab Job script for uploads to zScan

This script can be used to upload mobile applications to Zimperium (zScan) to be scanned for vulnerabilities. Using this script simplifies integrating mobile application security testing into CI/CD process and enables detection and remediation of vulnerabilities earlier in the application SDLC.

For more information on zScan, please see [Continuous Mobile Application Security Scanning](https://www.zimperium.com/zscan/).

## Prerequisites

1. Zimperium [MAPS](https://www.zimperium.com/mobile-app-protection/) license that includes zScan functionality.
2. API credentials with permissions to upload binaries
3. A valid application binary (.ipa, .apk, etc.), either built by the current pipeline or otherwise accessible by the script.

## Parameters

We recommend using GitLab [Variables](https://docs.gitlab.com/ee/ci/variables/#define-a-cicd-variable-in-the-ui) to provide parameters to the script.  Select [Masked](https://docs.gitlab.com/ee/ci/variables/#mask-a-cicd-variable) or [Masked and hidden](https://docs.gitlab.com/ee/ci/variables/#hide-a-cicd-variable) under Visibility, as needed.  Please refer to the [GitLab Documentation](https://docs.gitlab.com/ee/ci/variables/) for other ways to supply parameters to the script.

### Mandatory

These parameters are mandatory, _unless_ a default value is available as described below. 

- **ZSCAN_SERVER_URL**: console base URL, e.g., `https://ziap.zimperium.com/`.
- **ZSCAN_CLIENT_ID** and **ZSCAN_CLIENT_SECRET**: API credentials that can be obtained from the console.
- **ZSCAN_INPUT_FILE**: the path to the binary relative to the current workspace.
- **ZSCAN_TEAM_NAME**: name of the team to which this application belongs.  This is required only if submitting the application for the first time; values are ignored if the application already exists in the console and assigned to a team.  If not supplied, the application will be assigned to the 'Default' team
- **ZSCAN_REPORT_FORMAT**: the format of the scan report, either 'json' or 'sarif' (default).  If you plan on importing zScan results into GitLab Ultimate edition, please use sarif format.  For more information on the SARIF format, please see [OASIS Open](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).

### Optional

These parameters are optional, but may be used to supply additional information about the build and/or control the plugin's output.

- **ZSCAN_REPORT_LOCATION**: destination folder for the vulnerability report. If not provided, the report is stored in the current workspace. Report location and name are important for [Job Artifact](https://docs.gitlab.com/ee/ci/jobs/job_artifacts.html) collection.
- **ZSCAN_REPORT_FILE_NAME**: filename of the report. If not provided, the filename will be patterned as follows: zscan-results-AssessmentID-report_format.json, e.g., _zscan-results-123456789-sarif.json_.
- **ZSCAN_POLLING_INTERVAL**: wait time for polling the server in seconds. 30 seconds is the default.
- **ZSCAN_BRANCH**: source code branch that the build is based on.
- **ZSCAN_BUILD_NUMBER**: application build number.
- **ZSCAN_ENVIRONMENT**: target environment, e.g., uat, dev, prod.

## Usage

Please refer to [GitLab Documentation](https://docs.gitlab.com/ee/ci/jobs/) for instructions on using scripts in your GitLab pipelines.  Here's a _sample_ zScan job that uploads an Android application to zScan and converts zScan SARIF output into GitLab's SAST-compatible artifact:

```JSON
# Upload to zScan and wait for scan results
zScan:
  needs: [assembleDebug]
  interruptible: true
  stage: test
  script:
    - wget https://raw.githubusercontent.com/Zimperium/zscan-plugin-gitlab/refs/heads/master/zScan_v1.sh
    - chmod +x zScan_v1.sh
    - ./zScan_v1.sh
    # Optional
    - wget -O sarif-converter https://gitlab.com/ignis-build/sarif-converter/-/releases/v0.9.2/downloads/bin/sarif-converter-linux-amd64
    - chmod +x sarif-converter
    - ./sarif-converter --type sast $PLUGIN_REPORT_FILE_NAME zscan-report.json
  artifacts:
    name: "zScan Results"
    reports:
      sast:
        - zscan-report.json
```

The above example assumes that the variables are correctly configured, including server URL, client id/secret, and the input file. The optional section uses an open source SARIF-to-GitLab converter to convert zScan report into the format suitable for importing into [GitLab Security dashboard](https://docs.gitlab.com/ee/user/application_security/security_dashboard/).  The Dashboard is only available with the GitLab Ultimate edition.  If this step is not applicable, you can modify the Artifact section of the job to look like this:

```JSON
  artifacts:
    name: "zScan Results"
    paths:
      $PLUGIN_REPORT_FILE_NAME
```

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
