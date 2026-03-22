# QM-Gmp-Robot Action

- Action to run qm-gmp-robot tests.

#### Use Case

```yaml
jobs:
  test-gmp:
    name: Test GMP on Nightly VM's
    runs-on:
      - self-hosted
      - self-hosted-generic
    steps:
      - uses: actions/checkout@v3
      - name: Run qm gmp robot test
        uses: ./.github/actions/qm-gmp-robot
        with:
          host: <Host DN>
          user: <GMP user>
          password: <GMP password>
          token: <Github auth token>
```

## Action Configuration

| Input Variable     | Description                                                                          |          |
|--------------------|--------------------------------------------------------------------------------------|----------|
| config             | Robot config to use. Default: gmpv22.04                                              | Optional |
| socket             | Path to gvmd socket. Only needed for local connections. Default: /run/gvmd/gvmd.sock | Optional |
| host               | IP/DNS to gvmd host. Set to use ssh connection mode. Default: empty                  | Optional |
| user               | Gvmd login user. Default: admin                                                      | Optional |
| password           | Gvmd login password.                                                                 | Required |
| ref                | Github branch to checkout qm gmp robot tests. Default: main                          | Optional |
| repository         | Github repository to checkout qm gmp robot tests. Default: greenbone/qm-gmp-robot    | Optional |
| token              | Github token to checkout greenbone/qm-gmp-robot.                                     | Required |
| log-artifact       | Upload Robot log file as artifact. Default: true                                     | Optional |
| exclude-enterprise | Exclude enterprise tests. Default: false                                             | Optional |
