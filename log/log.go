package log

import (
	"fmt"
	"log"

	"golang.org/x/net/context"

	"github.com/homebot/dnswall/request"
	"github.com/homebot/dnswall/server"
)

type LogMiddleware struct{}

func (*LogMiddleware) Name() string {
	return "log"
}

func (*LogMiddleware) Serve(ctx context.Context, req *request.Request) server.Result {
	return server.FailOrNext(ctx)
}

func (*LogMiddleware) Mangle(ctx context.Context, req *request.Request, response request.Response) error {
	answer := "Not Resolved"
	if response.Res != nil && len(response.Res.Answer) > 0 {
		answer = fmt.Sprintf("%s", response.Res.Answer[0].String())
	}

	log.Printf("[log] %s requested %q class=%s type=%s, resolved to: %s", req.RemoteAddr().String(), req.Name(), req.Class(), req.Type(), answer)

	return nil
}
