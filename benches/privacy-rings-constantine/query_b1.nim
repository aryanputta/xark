import std/[monotimes, os, times]
import constantine/named/algebras
import constantine/platforms/abstractions
import constantine/math/arithmetic
import constantine/math/elliptic/[
  ec_multi_scalar_mul_parallel,
  ec_shortweierstrass_affine,
  ec_shortweierstrass_jacobian
]
import constantine/threadpool/threadpool
import query_bundle

type
  Bundle = object
    scalars: seq[BigInt[254]]
    # Constantine's field-property macros inspect the concrete Fp instantiation.
    bases: seq[EC_ShortW_Aff[Fp[BN254_Snarks], G1]]
    expected: EC_ShortW_Aff[Fp[BN254_Snarks], G1]

proc readG1(data: string, offset: var int): EC_ShortW_Aff[Fp[BN254_Snarks], G1] =
  result.x.fromBig(readInteger(data, offset, BaseModulus))
  result.y.fromBig(readInteger(data, offset, BaseModulus))
  if not result.isNeutral().bool and not isOnCurve(result.x, result.y, G1).bool:
    raise newException(ValueError, "G1 point in query bundle is off-curve")

proc loadBundle(path: string): Bundle =
  let (data, count) = readBundleData(path)
  var offset = HeaderSize
  result.scalars = newSeq[BigInt[254]](count)
  result.bases = newSeq[EC_ShortW_Aff[Fp[BN254_Snarks], G1]](count)
  for i in 0 ..< count:
    result.scalars[i] = readScalar(data, offset, i == 0)
    result.bases[i] = readG1(data, offset)
    skipCoordinates(data, offset, 4)
  result.expected = readG1(data, offset)
  skipCoordinates(data, offset, 4)

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
