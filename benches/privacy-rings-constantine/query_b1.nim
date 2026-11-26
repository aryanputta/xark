import std/[monotimes, os, strutils, times]
import constantine/named/algebras
import constantine/platforms/abstractions
import constantine/math/arithmetic
import constantine/math/io/io_bigints
import constantine/math/elliptic/[
  ec_multi_scalar_mul_parallel,
  ec_shortweierstrass_affine,
  ec_shortweierstrass_jacobian
]
import constantine/threadpool/threadpool

const
  Magic = "XKQMSM01"
  HeaderSize = 12
  FieldSize = 32
  RecordSize = 7 * FieldSize
  ReferenceSize = 6 * FieldSize
  BaseModulus = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47".parseHexStr()
  ScalarModulus = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001".parseHexStr()
  ConstantinePin = "4083170f19ec8dba15604bf0d443b5d852d634d6"

type
  Bundle = object
    scalars: seq[BigInt[254]]
    # Constantine's field-property macros inspect the concrete Fp instantiation.
    bases: seq[EC_ShortW_Aff[Fp[BN254_Snarks], G1]]
    expected: EC_ShortW_Aff[Fp[BN254_Snarks], G1]

proc checkCanonical(data: string, offset: int, modulus: string) =
  for i in 0 ..< FieldSize:
    if data[offset + i] < modulus[i]:
      return
    if data[offset + i] > modulus[i]:
      break
  raise newException(ValueError, "noncanonical field in query bundle")

proc readInteger(data: string, offset: var int, modulus: string): BigInt[254] =
  checkCanonical(data, offset, modulus)
  var bytes: array[FieldSize, byte]
  for i in 0 ..< FieldSize:
    bytes[i] = byte(data[offset + i])
  if not result.unmarshal(bytes, bigEndian):
    raise newException(ValueError, "invalid field width in query bundle")
  offset += FieldSize

proc readG1(data: string, offset: var int): EC_ShortW_Aff[Fp[BN254_Snarks], G1] =
  result.x.fromBig(readInteger(data, offset, BaseModulus))
  result.y.fromBig(readInteger(data, offset, BaseModulus))
  if not result.isNeutral().bool and not isOnCurve(result.x, result.y, G1).bool:
    raise newException(ValueError, "G1 point in query bundle is off-curve")

proc readG2Fields(data: string, offset: var int) =
  # The B1 lane only needs G1 arithmetic. Check the G2 fields' encodings
  # before stepping over the four coordinates of each unused G2 point.
  for i in 0 ..< 4:
    checkCanonical(data, offset, BaseModulus)
    offset += FieldSize

proc loadBundle(path: string): Bundle =
  let data = readFile(path)
  if data.len < HeaderSize or data[0 ..< Magic.len] != Magic:
    raise newException(ValueError, "invalid XKQMSM01 header")
  var count: uint64
  for i in 0 ..< 4:
    count = count or (uint64(ord(data[Magic.len + i])) shl (8 * i))
  let expectedSize = uint64(HeaderSize + ReferenceSize) + count * uint64(RecordSize)
  if count == 0 or uint64(data.len) != expectedSize:
    raise newException(ValueError, "invalid XKQMSM01 size or term count")

  var offset = HeaderSize
  result.scalars = newSeq[BigInt[254]](int(count))
  result.bases = newSeq[EC_ShortW_Aff[Fp[BN254_Snarks], G1]](int(count))
  for i in 0 ..< int(count):
    if i == 0 and (data[offset ..< offset + FieldSize - 1] != repeat('\0', FieldSize - 1) or
                   data[offset + FieldSize - 1] != '\1'):
      raise newException(ValueError, "query bundle lacks the constant-one scalar")
    result.scalars[i] = readInteger(data, offset, ScalarModulus)
    result.bases[i] = readG1(data, offset)
    readG2Fields(data, offset)
  result.expected = readG1(data, offset)
  readG2Fields(data, offset)

proc requireB1(output: EC_ShortW_Jac[Fp[BN254_Snarks], G1],
               expected: EC_ShortW_Aff[Fp[BN254_Snarks], G1]) =
  let isIdentity = output.isNeutral().bool
  if isIdentity == expected.isNeutral().bool:
    if isIdentity:
      return
    var normalized: EC_ShortW_Aff[Fp[BN254_Snarks], G1]
    normalized.affine(output)
    if (normalized == expected).bool:
      return
  raise newException(ValueError, "b1 disagrees with the Arkworks result")

proc parseCount(arg: string, minimum, maximum: int): int =
  result = parseInt(arg)
  if result < minimum or result > maximum:
    raise newException(ValueError, "invalid thread, sample or warmup count")

proc main() =
  if paramCount() < 2 or paramCount() > 4:
    raise newException(ValueError,
      "usage: constantine-b1 <XKQMSM01 bundle> <threads> [samples [warmups]]")
  let threads = parseCount(paramStr(2), 1, int(high(cint)))
  let samples = if paramCount() >= 3: parseCount(paramStr(3), 1, high(int)) else: 30
  let warmups = if paramCount() == 4: parseCount(paramStr(4), 0, high(int) - samples) else: 3
  if warmups > high(int) - samples:
    raise newException(ValueError, "sample and warmup count overflow")

  let bundle = loadBundle(paramStr(1))
  let pool = Threadpool.new(threads)
  defer: pool.shutdown()
  var timings = newSeqOfCap[int64](samples)
  for i in 0 ..< (warmups + samples):
    var output: EC_ShortW_Jac[Fp[BN254_Snarks], G1]
    let start = getMonoTime()
    pool.multiScalarMul_vartime_parallel(output, bundle.scalars, bundle.bases)
    let stop = getMonoTime()
    requireB1(output, bundle.expected)
    if i >= warmups:
      timings.add(inNanoseconds(stop - start))

  echo "query msm constantine verified: terms=", bundle.scalars.len,
    " threads=", pool.numThreads, " samples=", samples, " warmups=", warmups,
    " bundle=XKQMSM01 reference=arkworks scalar_repr=canonical-bigint",
    " constantine_commit=", ConstantinePin
  for i, ns in timings:
    echo "query msm constantine: query=b1 sample=", i + 1, " constantine_ns=", ns

when isMainModule:
  try:
    main()
  except CatchableError as error:
    stderr.writeLine("constantine-b1: ", error.msg)
    quit(1)
