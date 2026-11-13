/*
SPDX-FileCopyrightText: 2026 AndroidReLive_ZPH contributors
SPDX-License-Identifier: GPL-3.0-only

音频播放层（audio）
======================================
把 scrcpy 推过来的音频流接去浏览器播放：

  · 流里每个包：type:"configuration" 是解码器配置（Opus 即 OpusHead，
                  AAC 即 AudioSpecificConfig），
                  type:"data" 是一帧编码好的音频（pts 单位微秒）。
  · 用浏览器内置 AudioDecoder 解码 Opus / AAC → AudioData → 排进 AudioContext 播放。
  · gain 节点做音量 / 静音；AudioContext 在用户手势（点喇叭 / 页面任意点击）时 resume，
    绕过浏览器自动播放限制。

只依赖浏览器原生能力，不引第三方库。任何一步失败都只告警、不影响投屏画面。
每一步都会通过 log() 打到右侧运行日志，前缀 [音频]，方便排错。

这次修的坑（2026-11-13 第三轮）：
  1. 第二轮把 Opus 帧标 type:"key" 后解码已正常（日志出现「音频已解码一帧」）。
  2. 解出来的帧在播放环节全挂：交错格式分支调 AudioData.copyTo 时漏传了
     必填参数 planeIndex（交错格式整帧都在平面 0），浏览器直接抛
     "Required member is undefined"。已补 planeIndex:0。
  3. 播放错误同样加防刷屏计数（最多打 3 条）。

前两轮（2026-11-13）：
  1. decode 同步 DataError / closed 重建兜底 + 连续失败 3 次安静停 + isConfigSupported 探测。
  2. Opus 缺标准 OpusHead 时合成默认头（立体声 48k）。
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

/** OpusHead 魔数：前 8 字节必须是 "OpusHead" */
function isOpusHead(d) {
  if (!d || d.length < 8) return false;
  return (
    d[0] === 0x4f && d[1] === 0x70 && d[2] === 0x75 && d[3] === 0x73 && // "Opus"
    d[4] === 0x48 && d[5] === 0x65 && d[6] === 0x61 && d[7] === 0x64    // "Head"
  );
}

/** 合成一个标准 OpusHead（channel mapping family 0，无扩展表）。scrcpy 默认立体声 48k。 */
function makeOpusHead(channels = 2, sampleRate = 48000) {
  const buf = new Uint8Array(19);
  const magic = "OpusHead";
  for (let i = 0; i < 8; i += 1) buf[i] = magic.charCodeAt(i);
  buf[8] = 1; // version
  buf[9] = channels; // channel count
  // 10-11: preskip (LE) = 0
  buf[12] = sampleRate & 0xff;
  buf[13] = (sampleRate >> 8) & 0xff;
  buf[14] = (sampleRate >> 16) & 0xff;
  buf[15] = (sampleRate >> 24) & 0xff;
  // 16-17: output gain = 0
  buf[18] = 0; // channel mapping family 0
  return buf;
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
    // 解码时间戳：用单调递增计数器，避免服务端 pts 不连续 / 回退导致解码器报错
    this._ts = 0;
    this._lastTs = -1;
    // 解码器因某帧失败进入 closed 后的重建次数上限，避免无限重建
    this._decoderErrors = 0;
    // 最近一次成功配置（用于重建时复用）
    this._lastConfig = null;
    // 同类提示只打一次，别刷屏
    this._once = Object.create(null);
    // 连续解码失败计数：同步抛 DataError 不会让解码器进入 closed，旧兜底拦不住，
    // 这里连续失败 N 次就安静停掉，避免疯狂刷同一行错误。
    this._decodeFailStreak = 0;
    // 当前浏览器/配置不被 AudioDecoder 支持，直接放弃声音（不影响投屏）
    this._unsupported = false;
  }

  _logOnce(key, msg, level) {
    if (this._once[key]) return;
    this._once[key] = true;
    this.log(msg, level || "dim");
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

  _createDecoder() {
    this.decoder = new AudioDecoder({
      output: (data) => this._play(data),
      error: (e) => {
        this.log("音频解码器错误：" + (e?.message || e), "err");
        // 解码器一旦出错就进入 closed，后续 decode 必抛异常。标记失效，
        // 由 _pump 在下一包时自动重建（最多 3 次）。
        this._configured = false;
        this._decoderErrors += 1;
      },
    });
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
      this._createDecoder();
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
          this.log(
            "音频收到配置包，长度=" + (pkt.data ? pkt.data.length : 0) +
              "，首字节=" + (pkt.data && pkt.data.length ? "0x" + pkt.data[0].toString(16) : "空"),
            "dim"
          );
          await this._configure(pkt.data);
        } else if (pkt.type === "data") {
          if (this._unsupported) {
            this._logOnce("unsupported-stop", "浏览器不支持该音频解码，已忽略后续音频帧（不影响投屏）", "dim");
            break;
          }
          this._pktCount += 1;
          if (this._pktCount <= 3) this.log("音频数据包#" + this._pktCount + " pts=" + pkt.pts, "dim");

          // 解码器死了 / 还没配好：先尝试重建（带配置），建不起来就安静退出
          if (!this._configured || !this.decoder || this.decoder.state !== "configured") {
            if (this._decoderErrors < 3 && this._lastConfig) {
              this._logOnce("recreate", "音频解码器异常，正在自动重建（第 " + (this._decoderErrors + 1) + " 次）…", "warn");
              this._createDecoder();
              await this._configure(this._lastConfig.configData);
            }
            if (!this._configured) {
              if (!this._lastConfig) {
                this._logOnce("no-config", "尚未收到可用的音频解码配置，等配置包到达后再试", "dim");
                continue;
              }
              this._logOnce("recreate-fail", "音频解码器重建后仍不可用，已停止音频（不影响投屏）", "err");
              break;
            }
          }

          // 空帧直接跳过，空数据喂给解码器必抛 DataError
          if (!pkt.data || pkt.data.byteLength === 0) {
            this._logOnce("empty-frame", "音频收到空数据帧，已跳过", "warn");
            continue;
          }

          try {
            // 时间戳单调递增：服务端 pts 偶尔回退 / 不连续会让解码器报错，
            // 这里用计数器保证严格递增。播放节奏由 _nextTime 控制，与 pts 无关。
            let ts = Number(pkt.pts ?? 0);
            if (this._lastTs < 0) this._ts = ts;
            else this._ts = Math.max(ts, this._lastTs + 1);
            this._lastTs = this._ts;
            // Opus 帧互相独立，WebCodecs 官方推荐统一标 key；AAC 沿用帧自身关键标记。
            const frameType = this._webCodec === "opus" ? "key" : (pkt.keyframe ? "key" : "delta");
            const chunk = new EncodedAudioChunk({
              type: frameType,
              timestamp: this._ts,
              data: pkt.data,
            });
            this.decoder.decode(chunk);
            // 解出来一帧就重置连续失败计数
            this._decodeFailStreak = 0;
          } catch (e) {
            this._decodeFailStreak += 1;
            // 第一次失败打完整诊断，后面只报次数，避免刷屏
            if (this._decodeFailStreak === 1) {
              const head = (pkt.data && pkt.data.byteLength >= 8)
                ? Array.from(pkt.data.slice(0, 8)).map((b) => "0x" + b.toString(16).padStart(2, "0")).join(" ")
                : "(数据过短)";
              this.log(
                "音频解码抛异常：" + (e?.name || "") + " " + (e?.message || e) +
                  " | 帧长=" + (pkt.data ? pkt.data.byteLength : 0) + " 帧头=" + head,
                "err"
              );
            } else if (this._decodeFailStreak === 3) {
              this.log(
                "音频解码连续失败 3 次（已停止音频，不影响投屏）。把上面那条「音频解码抛异常」整行贴给我，重点看 帧长/帧头/错误名。",
                "err"
              );
            }
            // 连续失败 3 次直接安静退出，别再刷
            if (this._decodeFailStreak >= 3) break;
          }
        } else {
          this.log("音频未知包类型：" + JSON.stringify(pkt.type), "warn");
        }
      }
    } catch (e) {
      this.log("音频流读取结束/出错：" + (e?.message || e), "warn");
    }
  }

  async _configure(configData) {
    let channels = 2;
    let sampleRate = 48000;
    let headForCodec = configData ? new Uint8Array(configData) : null;

    if (this._webCodec === "opus") {
      if (isOpusHead(headForCodec)) {
        channels = headForCodec[9] || 2;
      } else {
        // 服务端没给标准 OpusHead（空包 / 数据帧当配置）：合成一个标准头
        if (configData && configData.length >= 10 && configData[9]) channels = configData[9];
        headForCodec = makeOpusHead(channels, sampleRate);
        this.log(
          "未收到标准 OpusHead（长度=" + (configData ? configData.length : 0) + "），已合成默认头：声道=" + channels + " 采样率=" + sampleRate,
          "warn"
        );
      }
    } else if (this._webCodec === "mp4a.40.2") {
      const parsed = parseAacConfig(configData);
      if (parsed) {
        channels = parsed.channels;
        sampleRate = parsed.sampleRate;
      }
    }

    // 先用 isConfigSupported 探一下这个浏览器到底认不认当前 codec（部分环境
    // AudioDecoder 存在但 opus 实际不被支持，configure 会延迟报错或直接 decode 抛异常）
    if (typeof AudioDecoder !== "undefined" && AudioDecoder.isConfigSupported) {
      try {
        const probe = {
          codec: this._webCodec,
          sampleRate,
          numberOfChannels: channels,
        };
        if (headForCodec) probe.description = new Uint8Array(headForCodec);
        const sup = await AudioDecoder.isConfigSupported(probe);
        this.log("音频解码能力探测：" + (sup?.supported ? "支持 " : "不支持 ") + this._webCodec + "@" + sampleRate + "/" + channels + "ch", sup?.supported ? "ok" : "warn");
        if (!sup?.supported) {
          this.log("当前浏览器 AudioDecoder 不支持该音频配置，已跳过声音（不影响投屏）", "warn");
          this._unsupported = true;
          this.onState({ available: false, error: "AudioDecoder 不支持 " + this._webCodec });
          return;
        }
      } catch (e) {
        this.log("音频解码能力探测异常（继续尝试）：" + (e?.message || e), "warn");
      }
    }

    try {
      this.decoder.configure({
        codec: this._webCodec,
        sampleRate,
        numberOfChannels: channels,
        description: headForCodec ? new Uint8Array(headForCodec) : undefined,
      });
      this._configured = true;
      this._lastConfig = { configData: headForCodec ? new Uint8Array(headForCodec) : null, codec: this._webCodec };
      this._lastTs = -1; // 重新计时
      this.log("音频解码器配置完成：codec=" + this._webCodec + " 声道=" + channels + " 采样率=" + sampleRate, "ok");
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
        // 交错格式整帧数据都在平面 0；planeIndex 是 copyTo 的必填参数，漏了会抛异常
        audioData.copyTo(inter, { planeIndex: 0, format: fmt });
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
      // 播放出错同样防刷屏：最多打 3 条，之后安静跳过
      this._playErrors = (this._playErrors || 0) + 1;
      if (this._playErrors <= 3) {
        this.log("音频播放出错：" + (e?.message || e), "err");
      }
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
