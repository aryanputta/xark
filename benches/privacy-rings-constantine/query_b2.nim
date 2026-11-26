import std/[monotimes, os, times]
import constantine/named/algebras
import constantine/platforms/abstractions
import constantine/math/[arithmetic, extension_fields]
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
    bases: seq[EC_ShortW_Aff[QuadraticExt[Fp[BN254_Snarks]], G2]]
    expected: EC_ShortW_Aff[QuadraticExt[Fp[BN254_Snarks]], G2]

proc readG2(data: string, offset: var int): EC_ShortW_Aff[QuadraticExt[Fp[BN254_Snarks]], G2] =
  # XKQMSM01 stores the imaginary coefficient first. Constantine stores c0 first.
  result.x.coords[1].fromBig(readInteger(data, offset, BaseModulus))
  result.x.coords[0].fromBig(readInteger(data, offset, BaseModulus))
  result.y.coords[1].fromBig(readInteger(data, offset, BaseModulus))
  result.y.coords[0].fromBig(readInteger(data, offset, BaseModulus))
  if not result.isNeutral().bool and not isOnCurve(result.x, result.y, G2).bool:
    raise newException(ValueError, "G2 point in query bundle is off-curve")

proc loadBundle(path: string): Bundle =
  let (data, count) = readBundleData(path)
  var offset = HeaderSize
  result.scalars = newSeq[BigInt[254]](count)
  result.bases = newSeq[EC_ShortW_Aff[QuadraticExt[Fp[BN254_Snarks]], G2]](count)
  for i in 0 ..< count:
    result.scalars[i] = readScalar(data, offset, i == 0)
    skipCoordinates(data, offset, 2)
    result.bases[i] = readG2(data, offset)
  skipCoordinates(data, offset, 2)
  result.expected = readG2(data, offset)

proc requireB2(output: EC_ShortW_Jac[QuadraticExt[Fp[BN254_Snarks]], G2],
               expected: EC_ShortW_Aff[QuadraticExt[Fp[BN254_Snarks]], G2]) =
  let isIdentity = output.isNeutral().bool
  if isIdentity == expected.isNeutral().bool:
    if isIdentity:
      return
    var normalized: EC_ShortW_Aff[QuadraticExt[Fp[BN254_Snarks]], G2]
    normalized.affine(output)
    if (normalized == expected).bool:
      return
  raise newException(ValueError, "b2 disagrees with the Arkworks result")

proc main() =
  if paramCount() < 2 or paramCount() > 4:
    raise newException(ValueError,
      "usage: constantine-b2 <XKQMSM01 bundle> <threads> [samples [warmups]]")
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
    var output: EC_ShortW_Jac[QuadraticExt[Fp[BN254_Snarks]], G2]
    let start = getMonoTime()
    pool.multiScalarMul_vartime_parallel(output, bundle.scalars, bundle.bases)
    let stop = getMonoTime()
    requireB2(output, bundle.expected)
    if i >= warmups:
      timings.add(inNanoseconds(stop - start))

  echo "query msm constantine verified: query=b2 terms=", bundle.scalars.len,
    " threads=", pool.numThreads, " samples=", samples, " warmups=", warmups,
    " bundle=XKQMSM01 reference=arkworks scalar_repr=canonical-bigint",
    " constantine_commit=", ConstantinePin
  for i, ns in timings:
    echo "query msm constantine: query=b2 sample=", i + 1, " constantine_ns=", ns

when isMainModule:
  try:
    main()
  except CatchableError as error:
    stderr.writeLine("constantine-b2: ", error.msg)
    quit(1)
