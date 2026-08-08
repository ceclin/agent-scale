# Third-party software

The `as-edge` multicall binary embeds source from two pinned upstream source
checkouts initialized by `cargo x init`:

- [fd](https://github.com/sharkdp/fd), available under MIT OR Apache-2.0;
- [ripgrep](https://github.com/BurntSushi/ripgrep), available under MIT OR
  Unlicense.

agent-scale binary distributions use the MIT option for both upstream works.
The alternative Apache-2.0 and Unlicense texts are included as well for
completeness. MIT is permissive and compatible with this project's Apache-2.0
license; redistribution requires retaining the upstream copyright and license
notices.

Their complete license texts and attribution files are read from the ignored
`.upstreams/fd/` and `.upstreams/ripgrep/` build-input cache and copied into
distribution artifacts. The pinned revisions live in `scripts/upstreams.lock`.
The ripgrep zsh completion also contains code from zsh-users under the
BSD-3-Clause license; its complete notice is included in
`licenses/ripgrep/LICENSE-BSD-3-Clause-zsh-users`.

Each release archive also contains a generated `THIRD_PARTY_LICENSES.html` for
the binary's complete non-development Rust dependency graph. Regenerate the
committed bundles with `./scripts/generate-licenses.sh`; `cargo x lint` checks
their input/output checksums against `Cargo.lock` and the package manifests
without rerunning the generator. Rust dependency license policy is independently
checked by `cargo deny check`.
