package socks5proxy

import (
 "context"
 "errors"
 "net"
 "net/http"
 "net/http/httptest"
 "sync/atomic"
 "testing"
 "time"

 "github.com/shikanon/socks5proxy/routing"
)

func TestOptionalUpstreamIsNotUsedForDirectTraffic(t *testing.T) {
 target:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Write([]byte("direct"))}));defer target.Close()
 rules,err:=routing.New([]string{"proxy.example"});if err!=nil{t.Fatal(err)}
 var calls atomic.Int32
 options:=ProxyOptions{Scope:"rules",Rules:rules,UpstreamDialContext:func(context.Context,string,string)(net.Conn,error){calls.Add(1);return nil,errors.New("offline")}}
 options,err=options.normalized();if err!=nil{t.Fatal(err)}
 auth,err:=CreateAuth("random","test-only");if err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel()
 conn,err:=dialDestination(ctx,target.Listener.Addr().String(),"100.64.0.2:8080",auth,options);if err!=nil{t.Fatal(err)};conn.Close()
 if calls.Load()!=0{t.Fatal("direct route leaked to overlay")}
 if _,err=dialDestination(ctx,"proxy.example:443","100.64.0.2:8080",auth,options);err==nil{t.Fatal("overlay failure unexpectedly succeeded")}
 if calls.Load()!=1{t.Fatal("upstream not used exactly once")}
}
func TestOptionalUpstreamIsBoundedAndPreservesSOCKSHandshake(t *testing.T){
 options,err:=(ProxyOptions{DialTimeout:time.Second}).normalized();if err!=nil{t.Fatal(err)}
 auth,err:=CreateAuth("random","test-only");if err!=nil{t.Fatal(err)}
 var calls atomic.Int32
 options.UpstreamDialContext=func(ctx context.Context,network,address string)(net.Conn,error){
  if _,ok:=ctx.Deadline();!ok{t.Error("missing upstream deadline")}
  if network!="tcp"||address!="100.64.0.2:8080"{t.Error("wrong upstream")}
  calls.Add(1)
  return nil,errors.New("expected fixture failure")
 }
 if _,err=dialDestination(context.Background(),"example.com:443","100.64.0.2:8080",auth,options);err==nil{t.Fatal("failed upstream accepted")}
 if calls.Load()!=1{t.Fatal("payload retry introduced")}
}
