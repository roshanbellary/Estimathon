mkdir -p /app/.streamlit

cat > /app/.streamlit/config.toml <<EOF
[server]
headless = true
port = $PORT
enableCORS = false
EOF