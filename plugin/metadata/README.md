# metadata
## 简介
metadata包提供了一个 API，允许插件将元数据添加到上下文中。每个元数据都存储在格式为`<plugin>/<name>` 的标签下。每个元数据作为 Func 返回。调用 Func 时返回元数据。如果某个 Func 执行时间很长，就需要自行提供某种形式的缓存。在处理一个查询时的元数据应该保持不变。
## 用例
Basic example:
```go
//
// Implement the Provider interface for a plugin p:
//
func (p P) Metadata(ctx context.Context, state request.Request) context.Context {
	metadata.SetValueFunc(ctx, "test/something", func() string { 
		   return "myvalue" 
	   })
	return ctx
    }
```
Basic example with caching:
```go
func (p P) Metadata(ctx context.Context, state request.Request) context.Context {
	cached := ""
	f := func() string {
	    if cached != "" {
		    return cached
	    }
	    cached = expensiveFunc()
	    return cached
	}
	metadata.SetValueFunc(ctx, "test/something", f)
	return ctx
    }

```


If you need access to this metadata from another plugin:
```go

    // ...
    valueFunc := metadata.ValueFunc(ctx, "test/something")
    value := valueFunc()
    // use 'value'

```