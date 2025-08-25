deploy:
	@if [ "$$(git rev-parse --abbrev-ref HEAD)" != "master" ]; then \
		echo "❌ Deploy only allowed on master branch"; \
		exit 1; \
	fi
	uv build
	uv publish
