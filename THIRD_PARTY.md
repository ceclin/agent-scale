# Third-party software

The `as-edge` multicall binary embeds source from two pinned upstream source
checkouts initialized by `cargo x init`:

- [fd](https://github.com/sharkdp/fd), available under MIT OR Apache-2.0;
- [ripgrep](https://github.com/BurntSushi/ripgrep), available under MIT OR
  Unlicense.

Their complete license texts and attribution files are read from the ignored
`.upstreams/fd/` and `.upstreams/ripgrep/` build-input cache and copied into
distribution artifacts. The pinned revisions live in `scripts/upstreams.lock`.
Rust dependency license metadata is checked by `cargo deny check` as part of
`cargo x lint`.
