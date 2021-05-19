package com.onepassword.burpanalyzer.util;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class SessionStateCache {
    private static final SessionStateCache instance = new SessionStateCache();

    public static SessionStateCache getInstance() {
        return instance;
    }

    private SessionStateCache() {}

    private final Map<String, State> cache = new HashMap<>();

    public Optional<Integer> findLatestRequestId(String sessionId) {
        return Optional.ofNullable(cache.get(sessionId)).flatMap(State::getLatestRequestId);
    }

    public Optional<byte[]> findSessionKey(String sessionId) {
        return Optional.ofNullable(cache.get(sessionId)).flatMap(State::getSessionKey);
    }

    public void setLatestRequestId(String sessionId, int requestId) {
        State state = cache.get(sessionId);

        if(state == null) {
            state = new State(requestId);
        } else{
            state.setLatestRequestId(requestId);
        }

        cache.put(sessionId, state);
    }

    public void setSessionKey(String sessionId, byte[] sessionKey) {
        State state = cache.get(sessionId);

        if(state == null) {
            state = new State(null, sessionKey);
        } else {
            state.sessionKey = sessionKey;
        }

        cache.put(sessionId, state);
    }

    private static class State {
        private Integer latestRequestId;
        private byte[] sessionKey;

        public State(Integer latestRequestId) {
            this.latestRequestId = latestRequestId;
        }

        public State(byte[] sessionKey) {
            this.sessionKey = sessionKey;
        }

        public State(Integer latestRequestId, byte[] sessionKey) {
            this.latestRequestId = latestRequestId;
            this.sessionKey = sessionKey;
        }

        public Optional<Integer> getLatestRequestId() {
            return Optional.ofNullable(latestRequestId);
        }

        public Optional<byte[]> getSessionKey() {
            return Optional.ofNullable(sessionKey);
        }

        public void setLatestRequestId(int requestId) {
            this.latestRequestId = requestId;
        }

        public void setSessionKey(byte[] sessionKey) {
            this.sessionKey = sessionKey;
        }

    }
}
