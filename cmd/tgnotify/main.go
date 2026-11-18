// Command tgnotify sends Telegram alerts from the shell or any language.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/shanki200801/tgnotify"
)

const version = "0.1.1"

const usage = `tgnotify - Telegram alerts from anywhere

Usage:
  tgnotify setup                                  interactive: save bot token + chat id
  tgnotify send [flags] [text]                    send text (reads stdin if no text)
  tgnotify file [flags] <path>                    send a file (-caption)
  tgnotify ask [flags] <question> <opt>...        block until a button is tapped; prints choice
  tgnotify prompt [flags] <question> <opt>...     send buttons now; prints message_id
  tgnotify collect [message_id]...                fetch button answers as JSON lines
  tgnotify run [flags] -- <cmd> [args]...         run a command, notify on finish
  tgnotify version

Common flags (before positional args):
  -title string   bold title line
  -level string   info | success | warn | error
  -silent         no notification sound
  -html           text is Telegram HTML (don't escape)
  -button "Text|https://url"   link button (repeatable; send only)

Config: env TGNOTIFY_TOKEN / TGNOTIFY_CHAT_ID, else ~/.config/tgnotify/config.json
`

type buttons [][]tgnotify.Button

func (b *buttons) String() string { return "" }
func (b *buttons) Set(v string) error {
	i := strings.LastIndex(v, "|")
	if i <= 0 {
		return errors.New(`button must be "Text|https://url"`)
	}
	*b = append(*b, []tgnotify.Button{{Text: v[:i], URL: v[i+1:]}})
	return nil
}

func commonFlags(fs *flag.FlagSet, o *tgnotify.Options) {
	fs.StringVar(&o.Title, "title", "", "title")
	fs.StringVar(&o.Level, "level", "", "info|success|warn|error")
	fs.BoolVar(&o.Silent, "silent", false, "silent")
	fs.BoolVar(&o.HTML, "html", false, "raw HTML")
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "tgnotify:", strings.TrimPrefix(err.Error(), "tgnotify: "))
	os.Exit(1)
}

func client() *tgnotify.Client {
	c, err := tgnotify.New()
	if err != nil {
		die(err)
	}
	return c
}

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	ctx := context.Background()
	cmd, args := os.Args[1], os.Args[2:]
	var o tgnotify.Options
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	switch cmd {
	case "send":
		var b buttons
		commonFlags(fs, &o)
		fs.Var(&b, "button", "Text|url")
		_ = fs.Parse(args)
		o.Buttons = b
		text := strings.Join(fs.Args(), " ")
		if fi, err := os.Stdin.Stat(); text == "" && err == nil && fi.Mode()&os.ModeCharDevice == 0 {
			in, _ := io.ReadAll(os.Stdin)
			text = strings.TrimRight(string(in), "\n")
		}
		if text == "" && o.Title == "" {
			die(errors.New("nothing to send"))
		}
		if _, err := client().Send(ctx, text, o); err != nil {
			die(err)
		}

	case "file":
		commonFlags(fs, &o)
		caption := fs.String("caption", "", "caption")
		_ = fs.Parse(args)
		if fs.NArg() != 1 {
			die(errors.New("usage: tgnotify file [-caption text] <path>"))
		}
		if _, err := client().SendFile(ctx, fs.Arg(0), *caption, o); err != nil {
			die(err)
		}

	case "ask", "prompt":
		commonFlags(fs, &o)
		timeout := fs.Duration("timeout", 10*time.Minute, "ask: how long to wait")
		asJSON := fs.Bool("json", false, "ask: print full answer as JSON")
		_ = fs.Parse(args)
		if fs.NArg() < 2 {
			die(fmt.Errorf("usage: tgnotify %s <question> <option>...", cmd))
		}
		c := client()
		if cmd == "prompt" {
			id, err := c.Prompt(ctx, fs.Arg(0), fs.Args()[1:], o)
			if err != nil {
				die(err)
			}
			fmt.Println(id)
			return
		}
		a, err := c.Ask(ctx, fs.Arg(0), fs.Args()[1:], *timeout, o)
		if errors.Is(err, tgnotify.ErrTimeout) {
			fmt.Fprintln(os.Stderr, "tgnotify: timed out")
			os.Exit(2)
		}
		if err != nil {
			die(err)
		}
		if *asJSON {
			_ = json.NewEncoder(os.Stdout).Encode(a)
		} else {
			fmt.Println(a.Choice)
		}

	case "collect":
		_ = fs.Parse(args)
		var ids []int64
		for _, s := range fs.Args() {
			id, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				die(fmt.Errorf("bad message id %q", s))
			}
			ids = append(ids, id)
		}
		got, err := client().Collect(ctx, ids...)
		if err != nil {
			die(err)
		}
		enc := json.NewEncoder(os.Stdout)
		for _, a := range got {
			_ = enc.Encode(a)
		}

	case "run":
		commonFlags(fs, &o)
		tail := fs.Int("tail", 15, "lines of output to include on failure")
		_ = fs.Parse(args)
		os.Exit(runCmd(ctx, fs.Args(), o, *tail))

	case "setup":
		setup(ctx)

	case "version", "-v", "--version":
		fmt.Println("tgnotify", version)

	case "help", "-h", "--help":
		fmt.Print(usage)

	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
}

// tailWriter keeps the last n lines written to it.
type tailWriter struct {
	n     int
	lines []string
	part  string
}

func (t *tailWriter) Write(p []byte) (int, error) {
	s := strings.ReplaceAll(t.part+string(p), "\r", "\n")
	parts := strings.Split(s, "\n")
	t.part = parts[len(parts)-1]
	t.lines = append(t.lines, parts[:len(parts)-1]...)
	if len(t.lines) > t.n {
		t.lines = t.lines[len(t.lines)-t.n:]
	}
	return len(p), nil
}

func (t *tailWriter) String() string {
	l := t.lines
	if t.part != "" {
		l = append(l, t.part)
	}
	if len(l) > t.n {
		l = l[len(l)-t.n:]
	}
	out := []rune(strings.Join(l, "\n"))
	if len(out) > 3000 { // keep the end; must fit one message
		out = append([]rune("…"), out[len(out)-3000:]...)
	}
	return string(out)
}

func runCmd(ctx context.Context, argv []string, o tgnotify.Options, tailN int) int {
	if len(argv) == 0 {
		die(errors.New("usage: tgnotify run [flags] -- <cmd> [args]"))
	}
	c := client() // fail fast before running if unconfigured
	tw := &tailWriter{n: tailN}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = io.MultiWriter(os.Stdout, tw)
	cmd.Stderr = io.MultiWriter(os.Stderr, tw)
	start := time.Now()
	err := cmd.Run()
	dur := time.Since(start).Round(time.Second)
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		code = 127
	}
	name := strings.Join(argv, " ")
	if r := []rune(name); len(r) > 200 {
		name = string(r[:200]) + "…"
	}
	host, _ := os.Hostname()
	if o.Title == "" {
		o.Title = "Command finished"
		if code != 0 {
			o.Title = "Command failed"
		}
	}
	if o.Level == "" {
		o.Level = "success"
		if code != 0 {
			o.Level = "error"
		}
	}
	body := tgnotify.EscapeHTML(fmt.Sprintf("$ %s\nexit %d · %s · %s", name, code, dur, host))
	if code != 0 {
		if err != nil && ee == nil {
			body += "\n" + tgnotify.EscapeHTML(err.Error())
		}
		if t := tw.String(); t != "" {
			body += "\n<pre>" + tgnotify.EscapeHTML(t) + "</pre>"
		}
	}
	o.HTML = true
	if _, serr := c.Send(ctx, body, o); serr != nil {
		fmt.Fprintln(os.Stderr, "tgnotify:", serr)
	}
	return code
}

func setup(ctx context.Context) {
	in := bufio.NewReader(os.Stdin)
	fmt.Println("1. In Telegram, open @BotFather, send /newbot, and copy the token.")
	fmt.Print("Bot token: ")
	tok, _ := in.ReadString('\n')
	tok = strings.TrimSpace(tok)
	if tok == "" {
		die(errors.New("no token entered"))
	}
	cfg := tgnotify.Config{Token: tok, APIBase: os.Getenv("TGNOTIFY_API_BASE")}
	c := tgnotify.NewWithConfig(cfg)
	var me struct {
		Username string `json:"username"`
	}
	if err := c.Call(ctx, "getMe", map[string]string{}, &me); err != nil {
		die(fmt.Errorf("token rejected: %v", err))
	}
	fmt.Printf("2. Open https://t.me/%s and send it any message (e.g. /start). Waiting up to 2 min...\n", me.Username)
	deadline := time.Now().Add(2 * time.Minute)
	var offset int64
	for time.Now().Before(deadline) {
		var ups []struct {
			UpdateID int64 `json:"update_id"`
			Message  *struct {
				Chat struct {
					ID       int64  `json:"id"`
					Username string `json:"username"`
					Title    string `json:"title"`
				} `json:"chat"`
			} `json:"message"`
		}
		p := map[string]interface{}{"timeout": 20, "allowed_updates": []string{"message", "callback_query"}}
		if offset > 0 {
			p["offset"] = offset
		}
		if err := c.Call(ctx, "getUpdates", p, &ups); err != nil {
			die(err)
		}
		for _, u := range ups {
			offset = u.UpdateID + 1
			if u.Message == nil {
				continue
			}
			cfg.ChatID = strconv.FormatInt(u.Message.Chat.ID, 10)
			// Acknowledge so they don't linger.
			_ = c.Call(ctx, "getUpdates", map[string]interface{}{"offset": offset, "timeout": 0}, nil)
			if err := tgnotify.SaveConfig(cfg); err != nil {
				die(err)
			}
			c.ChatID = cfg.ChatID
			_, _ = c.Send(ctx, "tgnotify is connected. You'll get alerts here.", tgnotify.Options{Level: "success", Title: "Setup complete"})
			fmt.Printf("Saved chat %s to %s (mode 0600). Check Telegram for a test message.\n", cfg.ChatID, tgnotify.ConfigPath())
			return
		}
	}
	die(errors.New("no message received; send the bot a message and re-run setup"))
}
