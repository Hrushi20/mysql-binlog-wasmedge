# MySql Binlog EventListener using WasmEdge

Binlog events are tracked using Wasm log reader. 


<hr>

#### Build the project in rust

``` rust
cargo build --target wasm32-wasi
```

#### Start Mysql Docker container
```
docker-compose up -d
```

#### Run webassembly log reader using wasmedge
```
wasmedge target/wasm32-wasi/debug/sql.wasm  
```


