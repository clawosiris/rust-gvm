# QM-Browser-Tests Action

- Action to run qm browser tests.

## Use Case

```yaml
jobs:
  test-browser:
    name: Test BROWSER on Nightly VM's
    runs-on:
      - self-hosted
      - self-hosted-generic
    steps:
      - uses: actions/checkout@v3
      - name: Run qm browser
        uses: ./.github/actions/qm-browser-tests
        with:
          config-yaml: <YAML>
          token: <Github token>
```

## Config Yaml

```yaml
SETUP_CONFIG:
  TEST_GSM:
  GSM_TYPE:
  BROWSER: Chrome
  SELENIUM_SPEED: 0.5 seconds
  GMP_USER:
  GMP_PASSWORD:
  SSH_USER:
  SSH_PASSWORD:
  LOG_LOCATION: local
  INCLUDE_TAGS:
  EXCLUDE_TAGS:
  HEADLESS: yes

TEST_CONFIG:
  EMAIL_RECIPIENT:
  METASPLOITABLE_TARGET:
  WINDOMAIN_TARGET:
  WINDOMAIN_USER:
  WINDOMAIN_PASSWORD:
  WINWORKGROUP_TARGET:
  WINWORKGROUP_USER:
  WINWORKGROUP_PASSWORD:
```

## Action Configuration

| Input Variable     | Description                                                                          |          |
|--------------------|--------------------------------------------------------------------------------------|----------|
| config             | Robot config to use. Default: gos2204                                                | Optional |
| config-yaml        | Yaml config file as string. Single quotes are not allowed!                           | Required |
| ref                | Github branch to checkout qm browser tests. Default: main                            | Optional |
| repository         | Github repository to checkout qm gmp robot tests. Default: greenbone/qm-browser-tests| Optional |
| token              | Github token to checkout greenbone/qm-browser-tests.                                 | Required |
| log-artifact       | Upload Robot log file as artifact. Default: true                                     | Optional |
| chrome-version     | Chrome version to use. Default: 116.0.5845.96                                        | Optional |
