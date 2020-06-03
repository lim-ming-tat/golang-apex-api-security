go get -u github.com/GovTechSG/test-suites-apex-api-security

go test -v -cover -coverprofile=c.out

go tool cover -html=c.out -o coverage.html