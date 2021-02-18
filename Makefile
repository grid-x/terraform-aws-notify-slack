BRANCH := $(shell git rev-parse --abbrev-ref HEAD | sed 's/\//_/g')
COMMIT := $(shell git rev-list -1 HEAD | cut -c1-7)
DIST_TAG := ${BRANCH}.dirty-${COMMIT}

.PHONY: changelog release

changelog:
	git-chglog -o CHANGELOG.md --next-tag `semtag final -s minor -o`

release:
	semtag final -s minor

zip:
	zip -j -o functions/dist.zip functions/notify_slack.py

s3:
	aws s3 cp functions/dist.zip ${S3_BUCKET}/tf-aws-notify-slack.${DIST_TAG}.zip
