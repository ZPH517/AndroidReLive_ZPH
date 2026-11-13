/*
SPDX-FileCopyrightText: 2026 AndroidReLive_ZPH contributors
SPDX-License-Identifier: GPL-3.0-only

音频播放层（audio）
======================================
把 scrcpy 推过来的音频流接去浏览器播放：

  · 流里每个包：type:"configuration" 是解码器配置（Opus 即 OpusHead），
                  type:"data" 是一帧编码好的音频（pts 单位微秒）。
  · 用浏览器内置 AudioDecoder 解码 Opus / AAC → AudioData → 排进 AudioContext 播放。
  · gain 节点做音量 / 静音；AudioContext 在用户手势（点喇叭 / 页面任意点击）时 resume，
    绕过浏览器自动播放限制。

只依赖浏览器原生能力，不引第三方库。任何一步失败都只告警、不影响投屏画面。
每一步都会通过 log() 打到右侧运行日志，前缀 [音频]，方便排错。
*/

/** 解析 AAC AudioSpecificConfig，拿采样率与声道数（Opus 不需要这个，直接从 OpusHead 取） */
function parseAacConfig(data) {
  if (!data || data.length < 2) return null;
  const b0 = data[0];
  const b1 = data[1];
  // audioObjectType = (b0 >> 3) & 0x1F
  // samplingFreqIndex = ((b0 & 0x07) << 1) | (b1 >> 7)
  // channelConfig = (b1 >> 3) & 0x0F
  const samplingFreqIndex = ((b0 & 0x07) << 1) | ((b1 >> 7) & 0x01);
  const channelConfig = (b1 >> 3) & 0x0f;
  const freqTable = [
    96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350,
  ];
  const sampleRate = freqTable[samplingFreqIndex] || 48000;
  return { channels: channelConfig || 2, sampleRate };
}

export class AudioPlayer {
  constructor({ onState = () => {}, log = () => {} } = {}) {
    this.onState = onState;
    this.log = log;
    this.ctx = null;
    this.gain = null;
    this.decoder = null;
    this.reader = null;
    this.muted = false;
    this.volume = 1;
    this._webCodec = "opus";
    this._nextTime = 0;
    this._closed = false;
    this._configured = false;
    this._everResumed = false;
    this._gotConfig = false;
    this._pktCount = 0;
  }

  /** 在用户手势内调用，唤醒被浏览器自动播放策略暂停的 AudioContext */
  async resume() {
    if (!this.ctx) return false;
    if (this.ctx.state !== "running") {
      try {
        await this.ctx.resume();
      } catch (e) {
        this.log("音频唤醒失败：" + (e?.message || e), "err");
        return false;
      }
    }
    const running = this.ctx.state === "running";
    this.log("音频上下文状态：" + this.ctx.state, running ? "ok" : "warn");
    this.onState({ available: true, muted: this.muted, volume: this.volume, running });
    return running;
  }

  async start(codec, stream) {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) {
      this.log("当前浏览器不支持 Web Audio，无法播放设备声音", "err");
      this.onState({ available: false, error: "当前浏览器不支持 Web Audio" });
      return;
    }
    if (typeof AudioDecoder === "undefined") {
      this.log("当前浏览器不支持 WebCodecs 音频解码（AudioDecoder 不存在）", "err");
      this.onState({ available: false, error: "当前浏览器不支持 WebCodecs 音频解码" });
      return;
    }
    // 默认 48k（Opus 标准输出）；AAC 会按实际采样率重建
    this._webCodec = codec?.webCodecId === "mp4a.66" ? "mp4a.40.2" : (codec?.webCodecId || "opus");
    try {
      this.ctx = new Ctx({ sampleRate: 48000 });
    } catch {
      try {
        this.ctx = new Ctx();
      } catch (e) {
        this.log("无法创建音频上下文：" + (e?.message || e), "err");
        this.onState({ available: false, error: "无法创建音频上下文" });
        return;
      }
    }
    this.gain = this.ctx.createGain();
    this.gain.gain.value = this.muted ? 0 : this.volume;
    this.gain.connect(this.ctx.destination);

    try {
      this.decoder = new AudioDecoder({
        output: (data) => this._play(data),
        error: (e) => this.log("音频解码器错误：" + (e?.message || e), "err"),
      });
    } catch (e) {
      this.log("创建 AudioDecoder 失败：" + (e?.message || e), "err");
      this.onState({ available: false, error: "创建 AudioDecoder 失败：" + (e?.message || e) });
      return;
    }

    this.log("音频启动：解码器=" + this._webCodec + "，AudioContext 初始状态=" + this.ctx.state, "ok");
    this.reader = stream.getReader();
    this._pump();

    // 兜底：页面任意一次用户手势都尝试唤醒（绕过自动播放限制），只挂一次
    this._gestureResume = () => {
      this.resume();
      if (this._gestureResume) {
        window.removeEventListener("pointerdown", this._gestureResume);
        window.removeEventListener("keydown", this._gestureResume);
        this._gestureResume = null;
      }
    };
    window.addEventListener("pointerdown", this._gestureResume);
    window.addEventListener("keydown", this._gestureResume);

    this.onState({ available: true, muted: this.muted, volume: this.volume, running: this.ctx.state === "running" });
  }

  async _pump() {
    try {
      while (!this._closed) {
        const { value: pkt, done } = await this.reader.read();
        if (done) break;
        if (!pkt) continue;
        if (pkt.type === "configuration") {
          this._gotConfig = true;
          this.log("音频收到配置包，长度=" + (pkt.data ? pkt.data.length : 0), "dim");
          this._configure(pkt.data);
        } else if (pkt.type === "data") {
          this._pktCount += 1;
          if (this._pktCount <= 3) this.log("音频数据包#" + this._pktCount + " pts=" + pkt.pts, "dim");
          if (!this._configured) {
            // Opus 兜底：若服务端没发独立配置包，首帧数据往往就是 OpusHead
            if (this._webCodec === "opus" && pkt.data && pkt.data.length >= 19) {
              this.log("音频无独立配置包，用首帧数据作为 Opus 配置", "dim");
              this._configure(pkt.data);
            }
            if (!this._configured) continue;
          }
          try {
            const chunk = new EncodedAudioChunk({
              type: "delta",
              timestamp: Number(pkt.pts ?? 0),
              data: pkt.data,
            });
            this.decoder.decode(chunk);
          } catch (e) {
            this.log("音频解码抛异常：" + (e?.message || e), "err");
          }
        } else {
          this.log("音频未知包类型：" + JSON.stringify(pkt.type), "warn");
        }
      }
    } catch (e) {
      this.log("音频流读取结束/出错：" + (e?.message || e), "warn");
    }
  }

  _configure(configData) {
    let channels = 2;
    let sampleRate = 48000;
    if (this._webCodec === "opus" && configData && configData.length >= 10) {
      // OpusHead: 第 0~7 字节是 "OpusHead"，第 9 字节是 channel_count
      channels = configData[9] || 2;
    } else if (this._webCodec === "mp4a.40.2") {
      const parsed = parseAacConfig(configData);
      if (parsed) {
        channels = parsed.channels;
        sampleRate = parsed.sampleRate;
      }
    }
    try {
      this.decoder.configure({
        codec: this._webCodec,
        sampleRate,
        numberOfChannels: channels,
        description: configData ? new Uint8Array(configData) : undefined,
      });
      this._configured = true;
      this.log("音频解码器配置完成：声道=" + channels + " 采样率=" + sampleRate, "ok");
    } catch (e) {
      this.log("音频解码器配置失败：" + (e?.message || e), "err");
      this.onState({ available: false, error: "音频解码器初始化失败：" + (e?.message || e) });
      return;
    }
    // AAC 采样率若与已建好的上下文不同，重建一个匹配采样率的上下文（否则声音会畸变）
    if (this.ctx && Math.abs(this.ctx.sampleRate - sampleRate) > 1) {
      try {
        const newCtx = new (window.AudioContext || window.webkitAudioContext)({ sampleRate });
        this.gain.disconnect();
        this.gain = newCtx.createGain();
        this.gain.gain.value = this.muted ? 0 : this.volume;
        this.gain.connect(newCtx.destination);
        const old = this.ctx;
        this.ctx = newCtx;
        old.close().catch(() => {});
        this.log("已按采样率 " + sampleRate + " 重建音频上下文", "dim");
      } catch {
        /* 重建失败就用原来的，最多音质略差 */
      }
    }
  }

  _play(audioData) {
    try {
      if (!this.ctx) return;
      // 浏览器自动播放策略：在用户手势之外 ctx 可能 suspended，这里尝试恢复（可能无效，靠点击兜底）
      if (this.ctx.state === "suspended") {
        this.ctx.resume().catch(() => {});
      }
      const { numberOfChannels, numberOfFrames, sampleRate } = audioData;
      if (!numberOfFrames || !numberOfChannels) {
        audioData.close();
        return;
      }
      if (this._pktCount <= 3) this.log("音频已解码一帧，ctx 状态=" + this.ctx.state, "dim");
      const ab = this.ctx.createBuffer(numberOfChannels, numberOfFrames, sampleRate);
      const fmt = audioData.format || "f32";
      const planar = String(fmt).endsWith("planar");
      if (planar) {
        for (let c = 0; c < numberOfChannels; c += 1) {
          const ch = new Float32Array(numberOfFrames);
          audioData.copyTo(ch, { planeIndex: c, format: fmt });
          ab.copyToChannel(ch, c);
        }
      } else {
        const inter = new Float32Array(numberOfFrames * numberOfChannels);
        audioData.copyTo(inter, { format: fmt });
        for (let c = 0; c < numberOfChannels; c += 1) {
          const ch = new Float32Array(numberOfFrames);
          for (let i = 0; i < numberOfFrames; i += 1) ch[i] = inter[i * numberOfChannels + c];
          ab.copyToChannel(ch, c);
        }
      }
      audioData.close();

      const dur = numberOfFrames / sampleRate;
      // 顺序排期：落后就追到当前时间；若因暂停/卡顿导致排期太靠前太多也拉回，避免越积越多
      if (this._nextTime < this.ctx.currentTime) this._nextTime = this.ctx.currentTime + 0.03;
      else if (this._nextTime > this.ctx.currentTime + 0.5) this._nextTime = this.ctx.currentTime + 0.03;
      const src = this.ctx.createBufferSource();
      src.buffer = ab;
      src.connect(this.gain);
      src.start(this._nextTime);
      this._nextTime += dur;
    } catch (e) {
      this.log("音频播放出错：" + (e?.message || e), "err");
      try { audioData.close(); } catch {}
    }
  }

  setMuted(m) {
    this.muted = !!m;
    if (this.gain) this.gain.gain.value = this.muted ? 0 : this.volume;
    this.onState({ available: true, muted: this.muted, volume: this.volume, running: this.ctx?.state === "running" });
  }

  setVolume(v) {
    this.volume = Math.max(0, Math.min(1, v));
    if (this.gain && !this.muted) this.gain.gain.value = this.volume;
    this.onState({ available: true, muted: this.muted, volume: this.volume, running: this.ctx?.state === "running" });
  }

  stop() {
    this._closed = true;
    if (this._gestureResume) {
      window.removeEventListener("pointerdown", this._gestureResume);
      window.removeEventListener("keydown", this._gestureResume);
      this._gestureResume = null;
    }
    try { this.reader?.cancel(); } catch {}
    try { this.decoder?.close(); } catch {}
    try { this.ctx?.close(); } catch {}
    this.onState({ available: false, muted: this.muted, volume: this.volume });
  }
}
