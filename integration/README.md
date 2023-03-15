# Step CLI Integration Tests

## How To Run

Run all the integration tests:
```
make integration
```

Run only integration tests that match a regex:
```
go test -tags=integration ./integration/... -run <REGEX>
```
