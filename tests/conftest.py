import tenacity

# Disable all retries.
tenacity.retry = lambda *a, **kw: (lambda f: f)
