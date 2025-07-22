FROM --platform=$BUILDPLATFORM python:3.11 as builder

WORKDIR /app

COPY . .

RUN pip install pyinstaller && \
    pip install -r requirements.txt && \
    pyinstaller --onefile --hidden-import=build_info --runtime-hook=build_info.py main.py

FROM scratch

WORKDIR /app
COPY --from=builder /app/dist/main /
CMD ["./main"]