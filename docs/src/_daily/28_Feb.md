
## Error Handling

- `anyhow` is great for application based errors where you just need to propagate it to humans. But its not good for libraries which need both debug(programmer facing) and display(end user facing).
- So, use `thiserror` instead.