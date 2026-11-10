package scantemplate_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/scantemplate"
)

func TestRunnerBoundsActualSubprocessOutputAndErrorFile(t *testing.T) {
	dir := t.TempDir()
	source := `package main
import("fmt";"os";"strings")
func main(){
 if len(os.Args)>1&&os.Args[1]=="-version"{fmt.Println("Nuclei Engine Version: v3.4.10");return}
 data:=strings.Repeat("x",13<<20)
 switch os.Getenv("ARTEX_ENGINE_TEST_MODE") {
 case "stdout":fmt.Print(data)
 case "stderr":fmt.Fprint(os.Stderr,data)
 case "errorfile":for i,arg:=range os.Args {if arg=="-elog" {if err:=os.WriteFile(os.Args[i+1],[]byte(data),0600);err!=nil{panic(err)}}};fmt.Println("{\"matcher-status\":false}")
 }
}`
	path := filepath.Join(dir, "engine.go")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	engine := filepath.Join(dir, "engine")
	if runtime.GOOS == "windows" {
		engine += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", engine, path).CombinedOutput(); err != nil {
		t.Fatalf("build subprocess: %v %s", err, out)
	}
	t.Setenv("ARTEX_NUCLEI_PATH", engine)
	content := `id: bounded-check
info: {name: Bounded check, severity: info}
http: [{method: GET, path: ["{{BaseURL}}/"], matchers: [{type: status, status: [200]}]}]
`
	for _, mode := range []string{"stdout", "stderr", "errorfile"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ARTEX_ENGINE_TEST_MODE", mode)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_, err := scantemplate.Run(ctx, content, "http://127.0.0.1")
			if err == nil || !strings.Contains(err.Error(), "exceeded limit") {
				t.Fatalf("unbounded subprocess stream %s: %v", mode, err)
			}
		})
	}
}
