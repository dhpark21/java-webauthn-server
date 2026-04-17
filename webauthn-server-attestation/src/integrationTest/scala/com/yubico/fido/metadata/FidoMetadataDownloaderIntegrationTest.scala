package com.yubico.fido.metadata

import com.yubico.fido.metadata.TestCaches.cachedDefaultSettingsDownloader
import com.yubico.internal.util.CertificateParser
import com.yubico.webauthn.data.ByteArray
import org.junit.runner.RunWith
import org.scalatest.BeforeAndAfter
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import org.scalatest.tags.Network
import org.scalatest.tags.Slow
import org.scalatestplus.junit.JUnitRunner

import scala.jdk.CollectionConverters.ListHasAsScala
import scala.util.Success
import scala.util.Try

@Slow
@Network
@RunWith(classOf[JUnitRunner])
class FidoMetadataDownloaderIntegrationTest
    extends AnyFunSpec
    with Matchers
    with BeforeAndAfter {

  describe("FidoMetadataDownloader with default settings") {
    val downloader = cachedDefaultSettingsDownloader.build()

    it("downloads and verifies the root cert and BLOB successfully.") {
      val blob = Try(TestCaches.cacheSynchronized(downloader.loadCachedBlob))
      blob shouldBe a[Success[_]]
      blob.get should not be null
    }

    it(
      "does not encounter any CRLDistributionPoints entries in unknown format."
    ) {
      val blob = Try(TestCaches.cacheSynchronized(downloader.loadCachedBlob))
      blob shouldBe a[Success[_]]
      val trustRootCert =
        CertificateParser.parseDer(
          TestCaches.getTrustRootCache.get.get.getBytes
        )
      val certChain = TestCaches
        .cacheSynchronized(
          downloader
            .fetchHeaderCertChain(
              trustRootCert,
              FidoMetadataDownloader
                .parseBlob(TestCaches.getBlobCache.get.get)
                .getBlob
                .getHeader,
            )
        )
        .asScala :+ trustRootCert
      for { cert <- certChain } {
        withClue(
          s"Unknown CRLDistributionPoints structure in cert [${cert.getSubjectX500Principal}] : ${new ByteArray(cert.getEncoded)}"
        ) {
          CertificateParser
            .parseCrlDistributionPointsExtension(cert)
            .isAnyDistributionPointUnsupported should be(false)
        }
      }
    }
  }

}
