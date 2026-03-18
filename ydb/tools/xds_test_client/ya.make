PROGRAM()

PEERDIR(
    ydb/core/mon
    ydb/core/protos
    ydb/core/util
    ydb/library/yaml_config
    ydb/public/api/client/yc_private/servicecontrol
    ydb/public/sdk/cpp/src/library/grpc/client
)

SRCS(
    main.cpp
)

YQL_LAST_ABI_VERSION()

END()