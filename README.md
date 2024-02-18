# gatekeeper-core

`gatekeeper-core` is a library for interfacing with gatekeeper NFC tags.
If you're interested in making a project using gatekeeper, you're free to
use this library, but you might prefer using
[`gatekeeper-members`](https://docs.rs/gatekeeper-members)
which adds support for validating tags against the gatekeeper server,
getting secrets from environment variables, and provides a higher-level
interface that should reduce boilerplate for most common usecases.

## Example

It's pretty easy to connect to a reader and find tags:

```rs
let mut gatekeeper_reader =
  GatekeeperReader::new("pn532_uart:/dev/ttyUSB0".to_string(), realm)
    .expect("Failed to open gatekeeper");
for tag in gatekeeper_reader.get_nearby_tags() {
  if let Ok(association_id) = tag.authenticate() {
    println!("Association ID for tag: {association_id}");
  }
}
```

Check out the
[`examples`](https://github.com/ComputerScienceHouse/gatekeeper-core/tree/master/examples)
directory for a more comprehensive example.

## Dependencies

Make sure you have libfreefare and libnfc installed. Loads of distributions package these.

If you're having trouble, try building these versions locally, which are known to work well:

* [libfreefare-0.4.0](https://github.com/nfc-tools/libfreefare/releases/tag/libfreefare-0.4.0)
* [libnfc 1.8.0](https://github.com/nfc-tools/libnfc/releases/download/libnfc-1.8.0/libnfc-1.8.0.tar.bz2)
