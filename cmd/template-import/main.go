// Command template-import rebuilds a verified template catalog offline.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/scantemplate"
)

func main() {
	directory := flag.String("bundle", "", "bundle directory; default embedded official snapshot")
	flag.Parse()
	manifest, templates, err := scantemplate.OfficialBundle()
	if *directory != "" {
		manifest, templates, err = scantemplate.ReadBundle(os.DirFS(*directory))
	}
	if err != nil {
		log.Fatal(err)
	}
	dsn, _, err := db.DSN()
	if err != nil {
		log.Fatal(err)
	}
	database, err := db.Open(dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer database.Close()
	if err = database.ImportScanTemplateBundle(context.Background(), templates, false); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("imported=%d source=%s version=%s\n", len(templates), manifest.Repository, manifest.Version)
}
