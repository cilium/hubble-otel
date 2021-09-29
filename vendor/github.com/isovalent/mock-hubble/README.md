# A mock implementation of Hubble API

This project contains an implementation of Hubble API that can run as a server for various testing purposes.

There is a standalone `main` function in [`server/`](server), and a package that can be called from tests or
somehow otherwise in [`observer/`](observer).

Features:

- support for plain and compressed JSON files (i.e. `.json` & `.json.{gz,bz2,xz}`)
- all flows events in a given set of JSON files are replayed to every client with adjusted timestamps
- distance between consequetive flow event timestamps is respected
  - speed adjustment can be applied, e.g. -10 to slow down 10x, 250 to speed-up 200x
