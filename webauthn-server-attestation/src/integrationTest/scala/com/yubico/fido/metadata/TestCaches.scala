package com.yubico.fido.metadata

import com.yubico.webauthn.data.ByteArray

import java.util.Optional
import java.util.function.Consumer
import java.util.function.Supplier
import scala.jdk.OptionConverters.RichOption

object TestCaches {

  // Cache downloaded items to avoid unnecessary load on remote servers, and so tests don't have to wait for rate limiting

  private var trustRootCache: Option[ByteArray] = None
  val getTrustRootCache: Supplier[Optional[ByteArray]] = () =>
    trustRootCache.toJava
  val setTrustRootCache: Consumer[ByteArray] = trustRoot => {
    trustRootCache = Some(trustRoot)
  }

  private var blobCache: Option[ByteArray] = None
  val getBlobCache: Supplier[Optional[ByteArray]] = () => blobCache.toJava
  val setBlobCache: Consumer[ByteArray] = blob => { blobCache = Some(blob) }

  def cachedDefaultSettingsDownloader
      : FidoMetadataDownloader.FidoMetadataDownloaderBuilder =
    FidoMetadataDownloader
      .builder()
      .expectLegalHeader(
        "Retrieval and use of this BLOB indicates acceptance of the appropriate agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/"
      )
      .useDefaultTrustRoot()
      .useTrustRootCache(getTrustRootCache, setTrustRootCache)
      .useDefaultBlob()
      .useBlobCache(getBlobCache, setBlobCache)

  /** Evaluate <code>expr</code> with an exclusive lock on the test cache. */
  def cacheSynchronized[A](expr: => A): A = {
    this.synchronized(expr)
  }

}
