package com.onepassword.burpanalyzer.processing;

import java.util.Optional;

public class Result<ResultType, ErrorType extends BaseError> {
    private ResultType result;
    private ErrorType error;

    public Result(ResultType result) {
        this.result = result;
    }

    public Result(ErrorType error) {
        this.error = error;
    }

    public ResultType getResult() { return result; }
    public Optional<ResultType> checkResult() { return Optional.ofNullable(result); }
    public boolean isOk() { return result != null; }
    public ErrorType getError() { return error; }
}
