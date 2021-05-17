[![Actions Status](https://github.com/signalsciences/go-sigsci/workflows/build/badge.svg)](https://github.com/signalsciences/go-sigsci/actions) [![GoDoc](https://godoc.org/github.com/signalsciences/go-sigsci?status.svg)](https://godoc.org/github.com/signalsciences/go-sigsci) [![Go Report Card](https://goreportcard.com/badge/github.com/signalsciences/go-sigsci)](https://goreportcard.com/report/github.com/signalsciences/go-sigsci)

# go-sigsci
Go client library for the Signal Sciences API.


## :rotating_light: NOTICE :rotating_light:

Effective **May 17th 2021** the default branch will change from `master` to `main`. Run the following commands to update a local clone:
```
git branch -m master main
git fetch origin
git branch -u origin/main main
git remote set-head origin -a
```

## Installation

```
go get github.com/signalsciences/go-sigsci
```

## Usage

```
email := "[sigsci email]"
password := "[sigsci password]"
sc, err := sigsci.NewClient(email, password)
if err != nil {
        log.Fatal(err)
}
```

## Full example

```
package main

import (
        "log"

        sigsci "github.com/signalsciences/go-sigsci"
)

func main() {
        email := "[sigsci email]"
        password := "[sigsci password]"
        sc, err := sigsci.NewClient(email, password)
        if err != nil {
                log.Fatal(err)
        }

        agents, err := sc.ListAgents("testcorp", "www.mysite.com")
        if err != nil {
                log.Fatal(err)
        }

        log.Println(agents)
}
```
