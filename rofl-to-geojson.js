#!/usr/bin/env node
"use strict";

const fs = require("fs");

const DEFAULT_EXTENT = 32768;

function die(msg) {
  console.error(`ERROR: ${msg}`);
  process.exit(1);
}

function readVarint(buf, state) {
  let value = 0;
  let shift = 0;

  while (state.i < buf.length) {
    const b = buf[state.i++];

    value += (b & 0x7f) * 2 ** shift;

    if ((b & 0x80) === 0) {
      return value;
    }

    shift += 7;

    if (shift > 49) {
      throw new Error("varint too large");
    }
  }

  throw new Error("unexpected EOF in varint");
}

function parseProto(buf) {
  const state = {
    i: 0,
  };

  const out = [];

  while (state.i < buf.length) {
    const start = state.i;

    const key = readVarint(buf, state);

    const field = Math.floor(key / 8);

    const wire = key & 7;

    if (wire === 0) {
      const value = readVarint(buf, state);

      out.push({
        field,
        wire,
        start,
        end: state.i,
        value,
      });

      continue;
    }

    if (wire === 2) {
      const len = readVarint(buf, state);

      const from = state.i;

      const to = from + len;

      if (to > buf.length) {
        throw new Error(`invalid protobuf length at ${start}: ${len}`);
      }

      out.push({
        field,
        wire,
        start,
        end: to,

        value: buf.subarray(from, to),
      });

      state.i = to;

      continue;
    }

    if (wire === 1) {
      const to = state.i + 8;

      if (to > buf.length) {
        throw new Error("unexpected EOF in fixed64");
      }

      out.push({
        field,
        wire,
        start,
        end: to,

        value: buf.subarray(state.i, to),
      });

      state.i = to;

      continue;
    }

    if (wire === 5) {
      const to = state.i + 4;

      if (to > buf.length) {
        throw new Error("unexpected EOF in fixed32");
      }

      out.push({
        field,
        wire,
        start,
        end: to,

        value: buf.subarray(state.i, to),
      });

      state.i = to;

      continue;
    }

    throw new Error(`unsupported protobuf wire type ${wire} at ${start}`);
  }

  return out;
}

function parseOuterTile(buf) {
  let top = parseProto(buf);

  /*
   * Иногда тайл может быть
   * завернут еще в одно поле #1.
   */
  if (top.length === 1 && top[0].field === 1 && top[0].wire === 2) {
    top = parseProto(top[0].value);
  }

  const scalar = (fieldNumber) =>
    top.find((f) => f.field === fieldNumber && f.wire === 0)?.value;

  const x = scalar(1);

  const yTms = scalar(2);

  const z = scalar(3);

  if (![x, yTms, z].every(Number.isFinite)) {
    throw new Error("could not find tile x/y/z in protobuf wrapper");
  }

  const layers = top
    .filter((f) => f.field === 4 && f.wire === 2)
    .map((f, index) => {
      const fields = parseProto(f.value);

      const get = (fieldNumber, wire) =>
        fields.find((q) => q.field === fieldNumber && q.wire === wire)?.value;

      /*
       * По текущему sample:
       *
       * field 3 = ROFL payload
       * field 5 = layer name
       */
      const payload = get(3, 2);

      const nameRaw = get(5, 2);

      return {
        index,

        name: nameRaw ? nameRaw.toString("utf8") : `layer_${index}`,

        payload,
        fields,
      };
    })
    .filter((layer) => layer.payload);

  return {
    x,
    yTms,
    z,
    layers,
  };
}

function planarDeltaScore(payload, start, count, extent = DEFAULT_EXTENT) {
  /*
   * Проверяем структуру:
   *
   * int16 dx[count]
   * int16 dy[count]
   *
   * X и Y лежат раздельно,
   * каждая колонка delta-coded.
   */

  const columnBytes = count * 2;

  const xStart = start;

  const yStart = xStart + columnBytes;

  const end = yStart + columnBytes;

  if (end > payload.length) {
    return null;
  }

  let x = 0;
  let y = 0;

  let minX = Infinity;

  let minY = Infinity;

  let maxX = -Infinity;

  let maxY = -Infinity;

  let outside = 0;

  let boundaryHits = 0;

  for (let i = 0; i < count; i++) {
    const dx = payload.readInt16LE(xStart + i * 2);

    const dy = payload.readInt16LE(yStart + i * 2);

    x += dx;
    y += dy;

    if (x < minX) {
      minX = x;
    }

    if (x > maxX) {
      maxX = x;
    }

    if (y < minY) {
      minY = y;
    }

    if (y > maxY) {
      maxY = y;
    }

    if (x < -extent || x > extent * 2 || y < -extent || y > extent * 2) {
      outside++;
    }

    if (x === 0 || y === 0 || x === extent || y === extent) {
      boundaryHits++;
    }
  }

  const spanX = maxX - minX;

  const spanY = maxY - minY;

  const extentError =
    Math.abs(minX) +
    Math.abs(minY) +
    Math.abs(maxX - extent) +
    Math.abs(maxY - extent);

  const spanError = Math.abs(spanX - extent) + Math.abs(spanY - extent);

  const outsideRatio = outside / count;

  const boundaryRatio = boundaryHits / count;

  /*
   * Правильный sample дает:
   *
   * minX = 0
   * maxX = 32768
   * minY = 0
   * maxY = 32768
   */
  const score =
    100 -
    (extentError / extent) * 20 -
    (spanError / extent) * 10 -
    outsideRatio * 100 +
    Math.min(boundaryRatio * 10, 5);

  return {
    score,

    start,
    count,

    xStart,
    yStart,
    end,

    minX,
    minY,

    maxX,
    maxY,

    spanX,
    spanY,

    finalX: x,
    finalY: y,

    outside,
    boundaryHits,
  };
}

function scanRofl(payload) {
  if (
    payload.length < 12 ||
    payload.subarray(0, 4).toString("ascii") !== "ROFL"
  ) {
    throw new Error("ROFL magic missing");
  }

  const version = payload.readUInt32LE(4);

  const schemaCount = payload.readUInt32LE(8);

  /*
   * В sample:
   *
   * N
   * N
   * N
   *
   * где N = 9838.
   *
   * Далее geometry:
   *
   * int16 dx[N]
   * int16 dy[N]
   */

  const candidates = [];

  const scanLimit = Math.min(payload.length, 4096);

  for (let off = 12; off + 12 <= scanLimit; off += 4) {
    const a = payload.readUInt32LE(off);

    const b = payload.readUInt32LE(off + 4);

    const c = payload.readUInt32LE(off + 8);

    if (a >= 16 && a === b && b === c && a < 5_000_000) {
      candidates.push({
        count: a,

        countOffset: off,
      });
    }
  }

  let best = null;

  for (const candidate of candidates) {
    /*
     * X = count * 2 bytes
     * Y = count * 2 bytes
     */
    const geometryBytes = candidate.count * 4;

    for (
      let start = Math.max(candidate.countOffset + 12, 64);
      start + geometryBytes <= payload.length;
      start += 4
    ) {
      /*
       * В текущем sample перед
       * geometry есть 12 нулевых байт.
       */
      const zeroPad =
        start >= 12 &&
        payload.subarray(start - 12, start).every((v) => v === 0);

      if (!zeroPad) {
        continue;
      }

      const analysis = planarDeltaScore(payload, start, candidate.count);

      if (!analysis) {
        continue;
      }

      if (analysis.score < 50) {
        continue;
      }

      if (!best || analysis.score > best.planar.score) {
        best = {
          ...candidate,

          start,

          bytes: geometryBytes,

          score: analysis.score,

          planar: analysis,
        };
      }
    }
  }

  return {
    version,
    schemaCount,

    coordinateStream: best,
  };
}

function readPlanarDeltaGeometry(payload, stream) {
  const count = stream.count;

  const columnBytes = count * 2;

  const xStart = stream.start;

  const yStart = xStart + columnBytes;

  const dx = new Int16Array(count);

  const dy = new Int16Array(count);

  const x = new Int32Array(count);

  const y = new Int32Array(count);

  let px = 0;
  let py = 0;

  for (let i = 0; i < count; i++) {
    const vx = payload.readInt16LE(xStart + i * 2);

    const vy = payload.readInt16LE(yStart + i * 2);

    dx[i] = vx;
    dy[i] = vy;

    px += vx;
    py += vy;

    x[i] = px;
    y[i] = py;
  }

  return {
    count,

    xStart,
    yStart,

    end: yStart + columnBytes,

    dx,
    dy,

    x,
    y,
  };
}

function readContinuationColumn(payload, start, count) {
  if (start < 0 || start + count > payload.length) {
    throw new Error("continuation column outside payload");
  }

  const flags = new Uint8Array(count);

  for (let i = 0; i < count; i++) {
    const value = payload[start + i];

    if (value !== 0 && value !== 1) {
      throw new Error(`invalid continuation flag ${value} at ${start + i}`);
    }

    flags[i] = value;
  }

  return flags;
}

function buildGeometryParts(geometry, flags) {
  /*
   * DEBUG topology reconstruction.
   *
   * ВАЖНО:
   * binary 0/1 column больше НЕ считаем
   * надежной continuation mask.
   *
   * Геометрия режется по:
   * 1. очень длинному скачку;
   * 2. резкому развороту после длинного сегмента;
   * 3. коротким локальным цепочкам.
   */

  const parts = [];

  const count = geometry.count;

  const distances = [];

  for (let i = 0; i < count - 1; i++) {
    const dx = geometry.x[i + 1] - geometry.x[i];

    const dy = geometry.y[i + 1] - geometry.y[i];

    const d = Math.hypot(dx, dy);

    if (Number.isFinite(d) && d > 0) {
      distances.push(d);
    }
  }

  distances.sort((a, b) => a - b);

  const medianDistance = distances.length
    ? distances[Math.floor(distances.length / 2)]
    : 150;

  /*
   * Для sample median ~150.
   */
  const HARD_JUMP = Math.max(700, medianDistance * 5);

  const SOFT_JUMP = Math.max(300, medianDistance * 2.5);

  /*
   * Если предыдущий и следующий векторы
   * почти противоположны — это подозрительный
   * переход между объектами.
   */
  const TURN_BREAK_COS = Math.cos((145 * Math.PI) / 180);

  let current = [];
  let currentStart = 0;

  function flush(endIndex, reason) {
    if (current.length > 0) {
      parts.push({
        startIndex: currentStart,

        endIndex,

        coordinates: current,

        breakReason: reason,
      });
    }

    current = [];
  }

  function getPoint(i) {
    return [geometry.x[i], geometry.y[i]];
  }

  for (let i = 0; i < count; i++) {
    const p = getPoint(i);

    if (current.length === 0) {
      currentStart = i;
      current.push(p);
      continue;
    }

    const prev = current[current.length - 1];

    const dx = p[0] - prev[0];

    const dy = p[1] - prev[1];

    const distance = Math.hypot(dx, dy);

    let shouldBreak = false;
    let reason = null;

    /*
     * 1. Однозначно огромный скачок.
     */
    if (distance > HARD_JUMP) {
      shouldBreak = true;
      reason = "hard-spatial-jump";
    }

    /*
     * 2. Проверяем направление.
     */
    if (!shouldBreak && current.length >= 2) {
      const prev2 = current[current.length - 2];

      const ax = prev[0] - prev2[0];

      const ay = prev[1] - prev2[1];

      const aLen = Math.hypot(ax, ay);

      const bLen = distance;

      if (aLen > 0 && bLen > 0) {
        const cos = (ax * dx + ay * dy) / (aLen * bLen);

        /*
         * Резкий обратный прыжок сам по себе
         * допустим на маленьких деталях.
         *
         * Но если хотя бы один из сегментов
         * сравнительно длинный — скорее всего
         * начался другой объект.
         */
        if (cos < TURN_BREAK_COS && (aLen > SOFT_JUMP || bLen > SOFT_JUMP)) {
          shouldBreak = true;
          reason = "direction-reset";
        }
      }
    }

    /*
     * 3. binary flag пока используем только
     * как слабую подсказку.
     *
     * flag=0 разрывает геометрию ТОЛЬКО если
     * между точками и так есть заметный скачок.
     */
    const hasPreviousFlag = i > 0 && i - 1 < flags.length;

    if (
      !shouldBreak &&
      hasPreviousFlag &&
      flags[i - 1] === 0 &&
      distance > medianDistance * 1.5
    ) {
      shouldBreak = true;
      reason = "flag-zero-plus-gap";
    }

    if (shouldBreak) {
      flush(i - 1, reason);

      currentStart = i;
      current.push(p);

      continue;
    }

    current.push(p);
  }

  if (current.length > 0) {
    flush(count - 1, "end-of-stream");
  }

  return parts;
}

function samePoint(a, b) {
  return a[0] === b[0] && a[1] === b[1];
}

function signedRingArea(coordinates) {
  let area = 0;

  for (let i = 0; i < coordinates.length - 1; i++) {
    const a = coordinates[i];

    const b = coordinates[i + 1];

    area += a[0] * b[1] - b[0] * a[1];
  }

  return area / 2;
}

function isClosedRing(coordinates) {
  return (
    coordinates.length >= 4 &&
    samePoint(coordinates[0], coordinates[coordinates.length - 1])
  );
}

function decodeGeometryParts(geometry, flags) {
  const parts = buildGeometryParts(geometry, flags);

  const breakReasonCounts = {};

  for (const part of parts) {
    const reason = part.breakReason || "unknown";

    breakReasonCounts[reason] = (breakReasonCounts[reason] || 0) + 1;
  }

  const features = [];

  let lineCount = 0;
  let polygonCount = 0;
  let skippedSingletons = 0;

  for (let partIndex = 0; partIndex < parts.length; partIndex++) {
    const part = parts[partIndex];

    const coordinates = part.coordinates;

    /*
     * Одна точка пока бесполезна для
     * line/polygon output.
     */
    if (coordinates.length < 2) {
      skippedSingletons++;
      continue;
    }

    if (isClosedRing(coordinates)) {
      const area = signedRingArea(coordinates);

      features.push({
        type: "Feature",

        properties: {
          roflPartIndex: partIndex,
          roflStartIndex: part.startIndex,
          roflEndIndex: part.endIndex,
          vertexCount: coordinates.length,

          roflBreakReason: part.breakReason,

          roflGeometryGuess: "polygon-ring",

          signedArea: area,

          diagnostic: true,
        },

        geometry: {
          type: "Polygon",

          coordinates: [coordinates],
        },
      });

      polygonCount++;

      continue;
    }

    features.push({
      type: "Feature",

      properties: {
        roflPartIndex: partIndex,
        roflStartIndex: part.startIndex,
        roflEndIndex: part.endIndex,
        vertexCount: coordinates.length,

        roflBreakReason: part.breakReason,

        roflGeometryGuess: "line",

        diagnostic: true,
      },

      geometry: {
        type: "LineString",

        coordinates,
      },
    });

    lineCount++;
  }

  return {
    features,

    diagnostics: {
      flagCount: flags.length,

      partCount: parts.length,

      lineCount,
      polygonCount,

      skippedSingletons,

      breakReasonCounts,

      coveredCoordinateCount: Math.min(geometry.count, flags.length),

      uncoveredCoordinateCount: Math.max(0, geometry.count - flags.length),
    },
  };
}

function decodeUncoveredPoints(geometry, coveredCount) {
  const features = [];

  for (let i = coveredCount; i < geometry.count; i++) {
    features.push({
      type: "Feature",

      properties: {
        roflIndex: i,

        roflUncovered: true,

        diagnostic: true,
      },

      geometry: {
        type: "Point",

        coordinates: [geometry.x[i], geometry.y[i]],
      },
    });
  }

  return features;
}

function decodeDeltaColumns(geometry) {
  const features = [];

  for (let i = 0; i < geometry.count; i++) {
    features.push({
      type: "Feature",

      properties: {
        roflIndex: i,

        dx: geometry.dx[i],

        dy: geometry.dy[i],

        roflHypothesis: "planar-delta-int16",
      },

      geometry: {
        type: "Point",

        coordinates: [geometry.x[i], geometry.y[i]],
      },
    });
  }

  return features;
}

function rangeOfTypedArray(values) {
  let min = Infinity;

  let max = -Infinity;

  for (const value of values) {
    if (value < min) {
      min = value;
    }

    if (value > max) {
      max = value;
    }
  }

  return {
    min,
    max,
  };
}

function inspectPostGeometry(payload, geometry) {
  const start = geometry.end;

  /*
   * Сразу после XY в текущем
   * sample идет большой блок нулей.
   */
  let zeroEnd = start;

  while (zeroEnd < payload.length && payload[zeroEnd] === 0) {
    zeroEnd++;
  }

  /*
   * Затем ищем длинный byte stream,
   * состоящий только из 0/1.
   */
  let binaryStart = null;

  let binaryLength = 0;

  for (
    let candidate = zeroEnd;
    candidate < Math.min(payload.length, zeroEnd + 1024);
    candidate++
  ) {
    let i = candidate;

    while (i < payload.length && (payload[i] === 0 || payload[i] === 1)) {
      i++;
    }

    const length = i - candidate;

    if (length > binaryLength) {
      binaryStart = candidate;

      binaryLength = length;
    }
  }

  let binaryZeros = 0;

  let binaryOnes = 0;

  if (binaryStart !== null) {
    for (let i = 0; i < binaryLength; i++) {
      if (payload[binaryStart + i] === 0) {
        binaryZeros++;
      } else {
        binaryOnes++;
      }
    }
  }

  return {
    geometryEnd: start,

    zeroBlock: {
      start,

      end: zeroEnd,

      bytes: zeroEnd - start,

      uint32Count: (zeroEnd - start) / 4,
    },

    binaryColumn: {
      start: binaryStart,

      length: binaryLength,

      zeros: binaryZeros,

      ones: binaryOnes,
    },
  };
}

function dumpBinaryRegion(
  payload,
  start,
  byteLength = 4096,
  includeFloat = false,
) {
  const end = Math.min(payload.length, start + byteLength);

  const rows = [];

  for (let offset = start; offset + 4 <= end; offset += 4) {
    const row = {
      offset,

      relative: offset - start,

      hex: "0x" + offset.toString(16).padStart(6, "0"),

      bytes: Array.from(payload.subarray(offset, offset + 4))
        .map((v) => v.toString(16).padStart(2, "0"))
        .join(" "),

      u32: payload.readUInt32LE(offset),

      i32: payload.readInt32LE(offset),

      u16a: payload.readUInt16LE(offset),

      u16b: payload.readUInt16LE(offset + 2),

      i16a: payload.readInt16LE(offset),

      i16b: payload.readInt16LE(offset + 2),
    };

    if (includeFloat) {
      row.f32 = Number(payload.readFloatLE(offset).toPrecision(7));
    }

    rows.push(row);
  }

  return rows;
}

function dumpRoflStructure(payload, byteLength = 2048) {
  return dumpBinaryRegion(payload, 0, byteLength, true);
}

function analyzeIntegerColumn(
  payload,
  start,
  count,
  bytesPerValue,
  signed,
  geometryCount,
) {
  const end = start + count * bytesPerValue;

  if (start < 0 || end > payload.length) {
    return null;
  }

  const values = new Array(count);

  let min = Infinity;
  let max = -Infinity;

  let sum = 0;

  let zeros = 0;
  let ones = 0;

  let monotonicNonDecreasing = true;
  let strictlyIncreasing = true;

  let previous = null;

  const histogram = new Map();

  for (let i = 0; i < count; i++) {
    const offset = start + i * bytesPerValue;

    let value;

    if (bytesPerValue === 1) {
      value = signed ? payload.readInt8(offset) : payload.readUInt8(offset);
    } else if (bytesPerValue === 2) {
      value = signed
        ? payload.readInt16LE(offset)
        : payload.readUInt16LE(offset);
    } else if (bytesPerValue === 4) {
      value = signed
        ? payload.readInt32LE(offset)
        : payload.readUInt32LE(offset);
    } else {
      throw new Error(`unsupported bytesPerValue: ${bytesPerValue}`);
    }

    values[i] = value;

    if (value < min) {
      min = value;
    }

    if (value > max) {
      max = value;
    }

    sum += value;

    if (value === 0) {
      zeros++;
    }

    if (value === 1) {
      ones++;
    }

    if (previous !== null) {
      if (value < previous) {
        monotonicNonDecreasing = false;
      }

      if (value <= previous) {
        strictlyIncreasing = false;
      }
    }

    previous = value;

    /*
     * Histogram нужен в основном для маленьких
     * topology/count/type колонок.
     */
    if (value >= -16 && value <= 256) {
      histogram.set(value, (histogram.get(value) || 0) + 1);
    }
  }

  /*
   * Несколько сильных признаков topology.
   */
  const topologyHints = [];

  if (sum === geometryCount) {
    topologyHints.push("sum-equals-geometry-count");
  }

  if (values.length > 0 && values[values.length - 1] === geometryCount) {
    topologyHints.push("last-equals-geometry-count");
  }

  if (monotonicNonDecreasing && min >= 0 && max <= geometryCount) {
    topologyHints.push("monotonic-offset-candidate");
  }

  if (strictlyIncreasing && min >= 0 && max <= geometryCount) {
    topologyHints.push("strict-offset-candidate");
  }

  if (
    min >= 1 &&
    max <= 256 &&
    sum >= geometryCount * 0.8 &&
    sum <= geometryCount * 1.2
  ) {
    topologyHints.push("small-counts-near-geometry-count");
  }

  if (count === geometryCount) {
    topologyHints.push("length-equals-geometry-count");
  }

  if (count === geometryCount + 1) {
    topologyHints.push("length-equals-geometry-count-plus-one");
  }

  const smallHistogram = Array.from(histogram.entries())
    .sort((a, b) => a[0] - b[0])
    .slice(0, 64)
    .map(([value, frequency]) => ({
      value,
      frequency,
    }));

  /*
   * Не кладем тысячи значений в JSON.
   * Первых 32 и последних 16 достаточно.
   */
  return {
    start,
    end,

    count,
    bytesPerValue,
    signed,

    min,
    max,
    sum,

    zeros,
    ones,

    monotonicNonDecreasing,
    strictlyIncreasing,

    topologyHints,

    firstValues: values.slice(0, 32),

    lastValues: values.slice(Math.max(0, values.length - 16)),

    smallHistogram,
  };
}

function scoreTopologyCandidate(analysis, geometryCount) {
  if (!analysis) {
    return -Infinity;
  }

  let score = 0;

  const hints = new Set(analysis.topologyHints);

  if (hints.has("sum-equals-geometry-count")) {
    score += 100;
  }

  if (hints.has("last-equals-geometry-count")) {
    score += 100;
  }

  if (hints.has("strict-offset-candidate")) {
    score += 60;
  } else if (hints.has("monotonic-offset-candidate")) {
    score += 35;
  }

  if (hints.has("small-counts-near-geometry-count")) {
    score += 50;
  }

  if (hints.has("length-equals-geometry-count")) {
    score += 20;
  }

  if (hints.has("length-equals-geometry-count-plus-one")) {
    score += 30;
  }

  /*
   * Массив из одних нулей нам неинтересен,
   * даже если его длина подозрительно красивая.
   */
  if (analysis.zeros === analysis.count) {
    score -= 200;
  }

  /*
   * Маленькие значения характерны для:
   * vertex counts, geometry type, commands.
   */
  if (analysis.min >= 0 && analysis.max <= 64) {
    score += 15;
  }

  /*
   * Если сумма хоть примерно равна числу вершин,
   * это тоже интересно.
   */
  if (analysis.sum > 0) {
    const relativeError =
      Math.abs(analysis.sum - geometryCount) / geometryCount;

    if (relativeError < 0.01) {
      score += 40;
    } else if (relativeError < 0.05) {
      score += 20;
    }
  }

  return score;
}

function scanTopologyColumns(payload, start, geometryCount) {
  /*
   * FAST topology scanner.
   *
   * Старый вариант делал:
   *
   *   ~128000 offsets
   *   × ~10000 values
   *   × несколько типов
   *
   * что давало миллиарды операций.
   *
   * Теперь:
   * 1. сначала находим структурные границы;
   * 2. проверяем только небольшое число offsets;
   * 3. count-array scan ограничиваем разумным окном.
   */

  const candidates = [];
  const payloadEnd = payload.length;

  /*
   * Для нашего sample:
   *
   * geometryEnd = 40132
   *
   * Сразу после него идет длинный zero block.
   * Нам особенно интересны:
   *
   * - start самого zero block
   * - его конец
   * - следующие aligned offsets
   */

  let zeroEnd = start;

  while (zeroEnd < payloadEnd && payload[zeroEnd] === 0) {
    zeroEnd++;
  }

  /*
   * Собираем небольшой набор offsets,
   * которые реально имеют структурный смысл.
   */
  const offsetSet = new Set();

  function addOffset(value) {
    if (value >= start && value < payloadEnd) {
      offsetSet.add(value);
    }
  }

  /*
   * Сам geometryEnd.
   */
  addOffset(start);

  /*
   * Конец zero block и небольшая область вокруг него.
   */
  for (let delta = -64; delta <= 256; delta++) {
    addOffset(zeroEnd + delta);
  }

  /*
   * Ищем transitions:
   *
   * 0 → nonzero
   * nonzero → 0
   *
   * в первых 128 KB.
   *
   * Такие места намного интереснее случайных
   * offsets внутри column data.
   */
  const scanEnd = Math.min(payloadEnd, start + 128 * 1024);

  for (let i = start + 1; i < scanEnd; i++) {
    const previousZero = payload[i - 1] === 0;

    const currentZero = payload[i] === 0;

    if (previousZero !== currentZero) {
      /*
       * Добавляем небольшую область вокруг
       * transition с alignment-friendly offsets.
       */
      for (let delta = -8; delta <= 8; delta++) {
        addOffset(i + delta);
      }
    }
  }

  /*
   * Также проверяем каждые 4 KB —
   * дешево и иногда ловит начало aligned column.
   */
  for (let offset = start; offset < scanEnd; offset += 4096) {
    addOffset(offset);
  }

  const offsets = Array.from(offsetSet).sort((a, b) => a - b);

  /*
   * ----------------------------------------------------------------
   * A. Проверка N / N+1 колонок
   * ----------------------------------------------------------------
   */

  const exactCounts = [geometryCount, geometryCount + 1];

  for (const offset of offsets) {
    for (const bytesPerValue of [1, 2, 4]) {
      if (bytesPerValue > 1 && offset % bytesPerValue !== 0) {
        continue;
      }

      for (const count of exactCounts) {
        if (offset + count * bytesPerValue > payloadEnd) {
          continue;
        }

        /*
         * Topology практически наверняка unsigned.
         *
         * signed версии пока вообще не сканируем —
         * это уменьшает работу вдвое.
         */
        const analysis = analyzeIntegerColumn(
          payload,
          offset,
          count,
          bytesPerValue,
          false,
          geometryCount,
        );

        const score = scoreTopologyCandidate(analysis, geometryCount);

        if (score >= 30) {
          candidates.push({
            score,

            kind: `u${bytesPerValue * 8}`,

            ...analysis,
          });
        }
      }
    }
  }

  /*
   * ----------------------------------------------------------------
   * B. Поиск vertexCounts[]
   * ----------------------------------------------------------------
   *
   * Здесь НЕ сканируем каждый байт payload.
   * Проверяем только структурные offsets.
   */

  for (const offset of offsets) {
    for (const bytesPerValue of [1, 2]) {
      if (bytesPerValue === 2 && offset % 2 !== 0) {
        continue;
      }

      let sum = 0;
      let count = 0;
      let zeroCount = 0;

      /*
       * Реальных feature/ring должно быть
       * существенно меньше, чем vertices.
       *
       * Даже 5000 entries здесь очень щедро.
       */
      const maxEntries = Math.min(geometryCount, 5000);

      for (let i = 0; i < maxEntries; i++) {
        const pos = offset + i * bytesPerValue;

        if (pos + bytesPerValue > payloadEnd) {
          break;
        }

        const value =
          bytesPerValue === 1
            ? payload.readUInt8(pos)
            : payload.readUInt16LE(pos);

        /*
         * Для vertex count значения вроде 30000
         * бессмысленны.
         *
         * Это позволяет очень быстро отбрасывать
         * неподходящие regions.
         */
        if (value > 2048) {
          break;
        }

        if (value === 0) {
          zeroCount++;

          /*
           * Если начало массива почти всё нули,
           * это явно не vertexCounts.
           */
          if (count >= 32 && zeroCount > count * 0.8) {
            break;
          }
        }

        sum += value;
        count++;

        if (sum === geometryCount) {
          const analysis = analyzeIntegerColumn(
            payload,
            offset,
            count,
            bytesPerValue,
            false,
            geometryCount,
          );

          candidates.push({
            score: 200 - Math.min(zeroCount, 100),

            kind: `u${bytesPerValue * 8}-counts`,

            ...analysis,

            topologyHints: [
              ...analysis.topologyHints,
              "cumulative-sum-hits-geometry-count",
            ],
          });

          break;
        }

        if (sum > geometryCount) {
          break;
        }
      }
    }
  }

  /*
   * ----------------------------------------------------------------
   * C. Поиск monotonic offsets[]
   * ----------------------------------------------------------------
   *
   * Проверяем u16/u32 sequences от структурных offsets.
   *
   * Ищем:
   *
   *   0, 4, 11, 15, ... 9838
   */

  for (const offset of offsets) {
    for (const bytesPerValue of [2, 4]) {
      if (offset % bytesPerValue !== 0) {
        continue;
      }

      let previous = -1;
      let count = 0;

      const values = [];

      for (let i = 0; i < 5000; i++) {
        const pos = offset + i * bytesPerValue;

        if (pos + bytesPerValue > payloadEnd) {
          break;
        }

        const value =
          bytesPerValue === 2
            ? payload.readUInt16LE(pos)
            : payload.readUInt32LE(pos);

        if (value > geometryCount) {
          break;
        }

        if (value < previous) {
          break;
        }

        values.push(value);

        previous = value;
        count++;

        if (value === geometryCount && count >= 2) {
          const analysis = analyzeIntegerColumn(
            payload,
            offset,
            count,
            bytesPerValue,
            false,
            geometryCount,
          );

          candidates.push({
            score: 250,

            kind: `u${bytesPerValue * 8}-offsets`,

            ...analysis,

            topologyHints: [
              ...analysis.topologyHints,
              "monotonic-sequence-ends-at-geometry-count",
            ],
          });

          break;
        }
      }
    }
  }

  /*
   * ----------------------------------------------------------------
   * Result
   * ----------------------------------------------------------------
   */

  candidates.sort((a, b) => b.score - a.score || a.start - b.start);

  const unique = [];
  const seen = new Set();

  for (const candidate of candidates) {
    const key = [
      candidate.start,
      candidate.bytesPerValue,
      candidate.count,
      candidate.kind,
    ].join(":");

    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    unique.push(candidate);

    if (unique.length >= 100) {
      break;
    }
  }

  return {
    geometryCount,

    scanStart: start,

    scanEnd,

    zeroBlock: {
      start,
      end: zeroEnd,

      bytes: zeroEnd - start,
    },

    testedOffsetCount: offsets.length,

    testedOffsets: offsets.slice(0, 256),

    candidateCount: unique.length,

    candidates: unique,
  };
}

function writeJson(outputArg, value, successLabel) {
  const text = JSON.stringify(value, null, 2);

  if (outputArg) {
    const filename = outputArg.split("=").slice(1).join("=");

    if (!filename) {
      die("--out= requires a filename");
    }

    fs.writeFileSync(filename, text);

    console.error(`${successLabel}: ${filename}`);
  } else {
    process.stdout.write(text + "\n");
  }
}

function inspectRegion(payload, start, end) {
  const rows = [];

  start = Math.max(0, start);

  end = Math.min(payload.length, end);

  /*
   * Выравниваем по 4 байта.
   */
  start -= start % 4;

  for (let offset = start; offset + 4 <= end; offset += 4) {
    const u32 = payload.readUInt32LE(offset);

    const i32 = payload.readInt32LE(offset);

    const u16a = payload.readUInt16LE(offset);

    const u16b = payload.readUInt16LE(offset + 2);

    const i16a = payload.readInt16LE(offset);

    const i16b = payload.readInt16LE(offset + 2);

    rows.push({
      offset,

      hexOffset: "0x" + offset.toString(16).padStart(6, "0"),

      bytes: Array.from(payload.subarray(offset, offset + 4))
        .map((v) => v.toString(16).padStart(2, "0"))
        .join(" "),

      u32,
      i32,

      u16: [u16a, u16b],

      i16: [i16a, i16b],
    });
  }

  return rows;
}

function makeStructureDump(payload, geometry, post) {
  const zeroEnd = post.zeroBlock.end;

  const binaryStart = post.binaryColumn.start;

  const binaryEnd =
    binaryStart !== null ? binaryStart + post.binaryColumn.length : null;

  return {
    geometryEnd: geometry.end,

    zeroBlock: {
      start: post.zeroBlock.start,

      end: zeroEnd,

      bytes: post.zeroBlock.bytes,
    },

    binaryColumn: {
      start: binaryStart,

      end: binaryEnd,

      length: post.binaryColumn.length,
    },

    /*
     * 256 байт перед концом zero block
     * и 512 после.
     */
    aroundZeroEnd: inspectRegion(payload, zeroEnd - 256, zeroEnd + 512),

    /*
     * Отдельно вокруг найденной 0/1 column.
     */
    aroundBinaryStart:
      binaryStart !== null
        ? inspectRegion(payload, binaryStart - 256, binaryStart + 512)
        : [],

    /*
     * И вокруг конца этой column.
     */
    aroundBinaryEnd:
      binaryEnd !== null
        ? inspectRegion(payload, binaryEnd - 256, binaryEnd + 1024)
        : [],
  };
}

function main() {
  const args = process.argv.slice(2);

  const input = args.find((arg) => !arg.startsWith("--"));

  if (!input) {
    die(
      "usage: node rofl-to-geojson.js tile.vt " +
        "[--mode=features|delta-columns|geometry-info|post-dump|column-scan|structure-dump|dump] " +
        "[--layer=N|name] " +
        "[--out=file.json]",
    );
  }

  const modeArg = args.find((arg) => arg.startsWith("--mode="));

  const mode = modeArg ? modeArg.split("=")[1] : "features";

  const allowedModes = [
    "features",
    "delta-columns",
    "geometry-info",
    "post-dump",
    "column-scan",
    "structure-dump",
    "dump",
  ];

  if (!allowedModes.includes(mode)) {
    die(`unknown mode: ${mode}`);
  }

  const outputArg = args.find((arg) => arg.startsWith("--out="));

  const layerArg = args.find((arg) => arg.startsWith("--layer="));

  const layerSelector = layerArg
    ? layerArg.split("=").slice(1).join("=")
    : null;

  const inputBuffer = fs.readFileSync(input);

  const tile = parseOuterTile(inputBuffer);

  const selectedLayers =
    layerSelector === null
      ? tile.layers
      : tile.layers.filter(
          (layer) =>
            String(layer.index) === layerSelector ||
            layer.name === layerSelector,
        );

  if (selectedLayers.length === 0) {
    die(`no matching layer: ${layerSelector}`);
  }

  /*
   * Raw header dump.
   */
  if (mode === "dump") {
    const layer = selectedLayers[0];

    if (
      layer.payload.length < 12 ||
      layer.payload.subarray(0, 4).toString("ascii") !== "ROFL"
    ) {
      die(`layer ${layer.name} does not contain ROFL payload`);
    }

    writeJson(
      outputArg,

      {
        layer: layer.name,

        payloadBytes: layer.payload.length,

        magic: layer.payload.subarray(0, 4).toString("ascii"),

        version: layer.payload.readUInt32LE(4),

        valueAt8: layer.payload.readUInt32LE(8),

        dump: dumpRoflStructure(layer.payload),
      },

      "ROFL dump written",
    );

    return;
  }

  const features = [];

  const diagnostics = [];

  for (const layer of selectedLayers) {
    let rofl;

    try {
      rofl = scanRofl(layer.payload);
    } catch (error) {
      diagnostics.push({
        layer: layer.name,

        error: error.message,
      });

      continue;
    }

    if (!rofl.coordinateStream) {
      diagnostics.push({
        layer: layer.name,

        version: rofl.version,

        schemaCount: rofl.schemaCount,

        error: "planar delta coordinate stream not confidently detected",
      });

      continue;
    }

    const geometry = readPlanarDeltaGeometry(
      layer.payload,
      rofl.coordinateStream,
    );

    const post = inspectPostGeometry(layer.payload, geometry);

    const continuationStart = post.binaryColumn.start;

    const continuationCount = post.binaryColumn.length;

    const xr = rangeOfTypedArray(geometry.x);

    const yr = rangeOfTypedArray(geometry.y);

    /*
     * Geometry diagnostics only.
     */
    if (mode === "geometry-info") {
      writeJson(
        outputArg,

        {
          layer: layer.name,

          roflVersion: rofl.version,

          schemaCount: rofl.schemaCount,

          count: geometry.count,

          countOffset: rofl.coordinateStream.countOffset,

          xStart: geometry.xStart,

          yStart: geometry.yStart,

          geometryEnd: geometry.end,

          minX: xr.min,

          maxX: xr.max,

          minY: yr.min,

          maxY: yr.max,

          finalX: geometry.x[geometry.count - 1],

          finalY: geometry.y[geometry.count - 1],

          score: rofl.coordinateStream.score,

          postGeometry: post,
        },

        "Geometry info written",
      );

      return;
    }

    /*
     * Dump first 16 KB after XY columns.
     *
     * Это сейчас главный режим
     * для reverse engineering topology.
     */
    if (mode === "post-dump") {
      writeJson(
        outputArg,

        {
          layer: layer.name,

          coordinateCount: geometry.count,

          xStart: geometry.xStart,

          yStart: geometry.yStart,

          geometryEnd: geometry.end,

          postGeometry: post,

          dump: dumpBinaryRegion(layer.payload, geometry.end, 16384),
        },

        "Post-geometry dump written",
      );

      return;
    }

    if (mode === "column-scan") {
      /*
       * Ищем настоящие topology/count/offset
       * колонки после XY.
       */
      const scan = scanTopologyColumns(
        layer.payload,
        geometry.end,
        geometry.count,
      );

      writeJson(
        outputArg,

        {
          layer: layer.name,

          roflVersion: rofl.version,

          schemaCount: rofl.schemaCount,

          geometry: {
            count: geometry.count,

            xStart: geometry.xStart,

            yStart: geometry.yStart,

            end: geometry.end,

            minX: xr.min,

            maxX: xr.max,

            minY: yr.min,

            maxY: yr.max,
          },

          /*
           * Для сравнения оставляем найденную
           * ранее 0/1 sequence.
           */
          previousBinaryGuess: {
            start: continuationStart,

            length: continuationCount,

            zeros: post.binaryColumn.zeros,

            ones: post.binaryColumn.ones,
          },

          topologyScan: scan,
        },

        "Column scan written",
      );

      return;
    }

    if (mode === "structure-dump") {
      const structure = makeStructureDump(layer.payload, geometry, post);

      writeJson(
        outputArg,

        {
          layer: layer.name,

          roflVersion: rofl.version,

          schemaCount: rofl.schemaCount,

          coordinateCount: geometry.count,

          structure,
        },

        "Structure dump written",
      );

      return;
    }

    if (mode === "features") {
      if (continuationStart === null || continuationCount <= 0) {
        throw new Error("continuation column not found");
      }

      const flags = readContinuationColumn(
        layer.payload,
        continuationStart,
        continuationCount,
      );

      const decoded = decodeGeometryParts(geometry, flags);

      for (const feature of decoded.features) {
        feature.properties.roflLayer = layer.name;

        feature.properties.roflVersion = rofl.version;

        features.push(feature);
      }

      diagnostics.push({
        layer: layer.name,

        version: rofl.version,

        coordinateCount: geometry.count,

        continuationStart,

        continuationCount,

        ...decoded.diagnostics,

        emittedFeatures: decoded.features.length,
      });

      continue;
    }

    /*
     * Default:
     * debug GeoJSON with decoded
     * native XY points.
     */
    const layerFeatures = decodeDeltaColumns(geometry);

    for (const feature of layerFeatures) {
      feature.properties.roflLayer = layer.name;

      feature.properties.roflVersion = rofl.version;

      feature.properties.roflSchemaCount = rofl.schemaCount;

      feature.properties.roflExtentAssumed = DEFAULT_EXTENT;

      feature.properties.roflCoordinateOffset = rofl.coordinateStream.start;

      feature.properties.roflCoordinateCount = rofl.coordinateStream.count;

      features.push(feature);
    }

    diagnostics.push({
      layer: layer.name,

      version: rofl.version,

      schemaCount: rofl.schemaCount,

      coordinateOffset: rofl.coordinateStream.start,

      coordinateCount: rofl.coordinateStream.count,

      countOffset: rofl.coordinateStream.countOffset,

      xStart: geometry.xStart,

      yStart: geometry.yStart,

      geometryEnd: geometry.end,

      minX: xr.min,

      maxX: xr.max,

      minY: yr.min,

      maxY: yr.max,

      finalX: geometry.x[geometry.count - 1],

      finalY: geometry.y[geometry.count - 1],

      score: Number(rofl.coordinateStream.score.toFixed(4)),

      postGeometry: post,

      emittedFeatures: layerFeatures.length,
    });
  }

  const geojson = {
    type: "FeatureCollection",

    name: "2gis-rofl-planar-delta-debug",

    roflDiagnostics: {
      warning:
        "XY planar delta decoding is strongly supported by the sample, but feature topology is not decoded yet.",

      tile: {
        x: tile.x,

        yTms: tile.yTms,

        z: tile.z,
      },

      layers: diagnostics,
    },

    features,
  };

  writeJson(outputArg, geojson, "GeoJSON written");
}

try {
  main();
} catch (error) {
  die(error.stack || error.message);
}
