#!/bin/bash
set -ex

bundle exec rspec spec && bundle exec rspec --tag integration -fd 2>/dev/null
