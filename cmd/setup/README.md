## Run Tutorial 

### Helps: 
```bash
go run main.go -h
```

### Defaults Params: 
```bash
go run main.go
```

### Run with custom parameters
```bash
# Chỉ định scheme path
go run main.go -scheme-path="custom/path/scheme.json"

# Chỉ định salt custom
go run main.go -salt="my_custom_salt_123"

# Bật verbose mode
go run main.go -verbose

# Kết hợp tất cả
go run main.go -scheme-path="data/bsw07.json" -salt="production_salt" -verbose
```