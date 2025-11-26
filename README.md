# Voice Engine

A robust media processing library for Rust, designed for building voice applications.

## Features

- **Codecs**: Support for G.711 (PCMA/PCMU), G.722, G.729, and Opus.
- **Media Processing**: Includes Jitter Buffer, Resampling, and DTMF handling.
- **Voice Activity Detection (VAD)**: Integrated Silero VAD.
- **Noise Reduction**: Built-in denoiser.
- **Speech Services**:
  - **ASR**: Aliyun, Tencent.
  - **TTS**: Aliyun, Deepgram, Tencent.
- **Transport**: RTP and WebRTC support.

## Usage

This library is intended to be used as a component in voice applications like `rustpbx`.
