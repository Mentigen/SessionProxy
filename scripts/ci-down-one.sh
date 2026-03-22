#!/bin/sh
set -e
goose -dir /migrations postgres "$TEST_DATABASE_URL" down
