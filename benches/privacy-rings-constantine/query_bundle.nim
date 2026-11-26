import std/strutils
import constantine/platforms/abstractions
import constantine/math/arithmetic
import constantine/math/io/io_bigints

const
  Magic = "XKQMSM01"
  HeaderSize* = 12
  FieldSize = 32
  RecordSize = 7 * FieldSize
  ReferenceSize = 6 * FieldSize
  BaseModulus* = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47".parseHexStr()
  ScalarModulus = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001".parseHexStr()
  ConstantinePin* = "4083170f19ec8dba15604bf0d443b5d852d634d6"

proc checkCanonical(data: string, offset: int, modulus: string) =
  for i in 0 ..< FieldSize:
    if data[offset + i] < modulus[i]:
      return
    if data[offset + i] > modulus[i]:
      break
  raise newException(ValueError, "noncanonical field in query bundle")

proc readInteger*(data: string, offset: var int, modulus: string): BigInt[254] =
  checkCanonical(data, offset, modulus)
  var bytes: array[FieldSize, byte]
  for i in 0 ..< FieldSize:
    bytes[i] = byte(data[offset + i])
  if not result.unmarshal(bytes, bigEndian):
    raise newException(ValueError, "invalid field width in query bundle")
  offset += FieldSize

proc readScalar*(data: string, offset: var int, first: bool): BigInt[254] =
  if first and (data[offset ..< offset + FieldSize - 1] != repeat('\0', FieldSize - 1) or
                data[offset + FieldSize - 1] != '\1'):
    raise newException(ValueError, "query bundle lacks the constant-one scalar")
  readInteger(data, offset, ScalarModulus)

proc skipCoordinates*(data: string, offset: var int, count: int) =
  for _ in 0 ..< count:
    checkCanonical(data, offset, BaseModulus)
    offset += FieldSize

proc readBundleData*(path: string): tuple[data: string, count: int] =
  let data = readFile(path)
  if data.len < HeaderSize or data[0 ..< Magic.len] != Magic:
    raise newException(ValueError, "invalid XKQMSM01 header")
  var count: uint64
  for i in 0 ..< 4:
    count = count or (uint64(ord(data[Magic.len + i])) shl (8 * i))
  let expectedSize = uint64(HeaderSize + ReferenceSize) + count * uint64(RecordSize)
  if count == 0 or uint64(data.len) != expectedSize:
    raise newException(ValueError, "invalid XKQMSM01 size or term count")
  (data, int(count))

proc parseCount*(arg: string, minimum, maximum: int): int =
  result = parseInt(arg)
  if result < minimum or result > maximum:
    raise newException(ValueError, "invalid thread, sample or warmup count")
