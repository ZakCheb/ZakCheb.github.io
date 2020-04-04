
# Install

Installs jekyll and the missing gem dependencies.
Dont install jekyl with apt but with bundler.

```bash
while true; do gem install $( jekyll serve  2>&1 | grep -oE " '([a-zA-Z_0-9-]+) \(" | grep -oE '[a-zA-Z_0-9-]+' ); done
```

Start the server

```bash
jekyll serve
```

