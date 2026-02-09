package com.jetbrains.signatureverifier.bouncycastle.cms

import org.bouncycastle.cms.SignerId
import org.bouncycastle.util.Iterable

class SignerInformationStore : Iterable<SignerInformation> {
  private var all: MutableList<SignerInformation>
  private val table: MutableMap<SignerId, MutableList<SignerInformation>> = mutableMapOf()

  /**
   * Create a store containing a single SignerInformation object.
   *
   * @param signerInfo the signer information to contain.
   */
  constructor(
    signerInfo: SignerInformation
  ) {
    all = mutableListOf()
    all.add(signerInfo)
    val sid = signerInfo.sID
    table[sid] = all
  }

  /**
   * Create a store containing a collection of SignerInformation objects.
   *
   * @param signerInfos a collection signer information objects to contain.
   */
  constructor(
    signerInfos: Collection<SignerInformation>
  ) {
    val it: Iterator<*> = signerInfos.iterator()
    while (it.hasNext()) {
      val signer = it.next() as SignerInformation
      val sid = signer.sID
      var list = table[sid]
      if (list == null) {
        list = mutableListOf()
        table[sid] = list
      }
      list.add(signer)
    }
    all = signerInfos.toMutableList()
  }

  /**
   * Return the first SignerInformation object that matches the
   * passed in selector. Null if there are no matches.
   *
   * @param selector to identify a signer
   * @return a single SignerInformation object. Null if none matches.
   */
  fun get(
    selector: SignerId
  ): SignerInformation? {
    val list = getSigners(selector)
    return if (list == null || list.isEmpty()) null else list.iterator().next()
  }

  /**
   * Return the number of signers in the collection.
   *
   * @return number of signers identified.
   */
  fun size(): Int {
    return all.size
  }

  /**
   * Return all signers in the collection
   *
   * @return a collection of signers.
   */
  val signers: MutableCollection<SignerInformation>
    get() = all.toMutableList()

  /**
   * Return possible empty collection with signers matching the passed in SignerId
   *
   * @param selector a signer id to select against.
   * @return a collection of SignerInformation objects.
   */
  fun getSigners(
    selector: SignerId
  ): Collection<SignerInformation>? {
    return if (selector.issuer != null && selector.subjectKeyIdentifier != null) {
      val results = mutableListOf<SignerInformation>()
      val match1 = getSigners(SignerId(selector.issuer, selector.serialNumber))
      if (match1 != null) {
        results.addAll(match1)
      }
      val match2 = getSigners(SignerId(selector.subjectKeyIdentifier))
      if (match2 != null) {
        results.addAll(match2)
      }
      results
    } else {
      val list = table[selector]
      if (list == null) ArrayList() else ArrayList(list)
    }
  }

  /**
   * Support method for Iterable where available.
   */
  override fun iterator(): MutableIterator<SignerInformation?> {
    return signers.iterator()
  }
}