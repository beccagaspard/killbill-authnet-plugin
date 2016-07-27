/**
 * This class is generated by jOOQ
 */
package com.womply.billing.killbill.plugins.jooq.tables.records;


import com.womply.billing.killbill.plugins.jooq.tables.AuthorizeNetTransactions;

import java.math.BigDecimal;
import java.sql.Timestamp;

import javax.annotation.Generated;

import org.jooq.Record1;
import org.jooq.impl.UpdatableRecordImpl;
import org.jooq.types.ULong;


/**
 * This class is generated by jOOQ.
 */
@Generated(
	value = {
		"http://www.jooq.org",
		"jOOQ version:3.6.2"
	},
	comments = "This class is generated by jOOQ"
)
@SuppressWarnings({ "all", "unchecked", "rawtypes" })
public class AuthorizeNetTransactionsRecord extends UpdatableRecordImpl<AuthorizeNetTransactionsRecord> {

	private static final long serialVersionUID = -956662284;

	/**
	 * Setter for <code>authorize_net_transactions.record_id</code>.
	 */
	public void setRecordId(ULong value) {
		setValue(0, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.record_id</code>.
	 */
	public ULong getRecordId() {
		return (ULong) getValue(0);
	}

	/**
	 * Setter for <code>authorize_net_transactions.request_id</code>.
	 */
	public void setRequestId(ULong value) {
		setValue(1, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.request_id</code>.
	 */
	public ULong getRequestId() {
		return (ULong) getValue(1);
	}

	/**
	 * Setter for <code>authorize_net_transactions.kb_payment_id</code>.
	 */
	public void setKbPaymentId(String value) {
		setValue(2, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.kb_payment_id</code>.
	 */
	public String getKbPaymentId() {
		return (String) getValue(2);
	}

	/**
	 * Setter for <code>authorize_net_transactions.kb_payment_method_id</code>.
	 */
	public void setKbPaymentMethodId(String value) {
		setValue(3, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.kb_payment_method_id</code>.
	 */
	public String getKbPaymentMethodId() {
		return (String) getValue(3);
	}

	/**
	 * Setter for <code>authorize_net_transactions.kb_payment_transaction_id</code>.
	 */
	public void setKbPaymentTransactionId(String value) {
		setValue(4, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.kb_payment_transaction_id</code>.
	 */
	public String getKbPaymentTransactionId() {
		return (String) getValue(4);
	}

	/**
	 * Setter for <code>authorize_net_transactions.kb_transaction_type</code>.
	 */
	public void setKbTransactionType(String value) {
		setValue(5, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.kb_transaction_type</code>.
	 */
	public String getKbTransactionType() {
		return (String) getValue(5);
	}

	/**
	 * Setter for <code>authorize_net_transactions.transaction_type</code>.
	 */
	public void setTransactionType(String value) {
		setValue(6, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.transaction_type</code>.
	 */
	public String getTransactionType() {
		return (String) getValue(6);
	}

	/**
	 * Setter for <code>authorize_net_transactions.authorize_net_customer_profile_id</code>.
	 */
	public void setAuthorizeNetCustomerProfileId(String value) {
		setValue(7, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.authorize_net_customer_profile_id</code>.
	 */
	public String getAuthorizeNetCustomerProfileId() {
		return (String) getValue(7);
	}

	/**
	 * Setter for <code>authorize_net_transactions.authorize_net_payment_profile_id</code>.
	 */
	public void setAuthorizeNetPaymentProfileId(String value) {
		setValue(8, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.authorize_net_payment_profile_id</code>.
	 */
	public String getAuthorizeNetPaymentProfileId() {
		return (String) getValue(8);
	}

	/**
	 * Setter for <code>authorize_net_transactions.authorize_net_transaction_id</code>.
	 */
	public void setAuthorizeNetTransactionId(String value) {
		setValue(9, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.authorize_net_transaction_id</code>.
	 */
	public String getAuthorizeNetTransactionId() {
		return (String) getValue(9);
	}

	/**
	 * Setter for <code>authorize_net_transactions.amount</code>.
	 */
	public void setAmount(BigDecimal value) {
		setValue(10, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.amount</code>.
	 */
	public BigDecimal getAmount() {
		return (BigDecimal) getValue(10);
	}

	/**
	 * Setter for <code>authorize_net_transactions.currency</code>.
	 */
	public void setCurrency(String value) {
		setValue(11, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.currency</code>.
	 */
	public String getCurrency() {
		return (String) getValue(11);
	}

	/**
	 * Setter for <code>authorize_net_transactions.auth_code</code>.
	 */
	public void setAuthCode(String value) {
		setValue(12, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.auth_code</code>.
	 */
	public String getAuthCode() {
		return (String) getValue(12);
	}

	/**
	 * Setter for <code>authorize_net_transactions.avs_result_code</code>.
	 */
	public void setAvsResultCode(String value) {
		setValue(13, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.avs_result_code</code>.
	 */
	public String getAvsResultCode() {
		return (String) getValue(13);
	}

	/**
	 * Setter for <code>authorize_net_transactions.cvv_result_code</code>.
	 */
	public void setCvvResultCode(String value) {
		setValue(14, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.cvv_result_code</code>.
	 */
	public String getCvvResultCode() {
		return (String) getValue(14);
	}

	/**
	 * Setter for <code>authorize_net_transactions.cavv_result_code</code>.
	 */
	public void setCavvResultCode(String value) {
		setValue(15, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.cavv_result_code</code>.
	 */
	public String getCavvResultCode() {
		return (String) getValue(15);
	}

	/**
	 * Setter for <code>authorize_net_transactions.account_type</code>.
	 */
	public void setAccountType(String value) {
		setValue(16, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.account_type</code>.
	 */
	public String getAccountType() {
		return (String) getValue(16);
	}

	/**
	 * Setter for <code>authorize_net_transactions.response_status</code>.
	 */
	public void setResponseStatus(String value) {
		setValue(17, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.response_status</code>.
	 */
	public String getResponseStatus() {
		return (String) getValue(17);
	}

	/**
	 * Setter for <code>authorize_net_transactions.response_message</code>.
	 */
	public void setResponseMessage(String value) {
		setValue(18, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.response_message</code>.
	 */
	public String getResponseMessage() {
		return (String) getValue(18);
	}

	/**
	 * Setter for <code>authorize_net_transactions.transaction_status</code>.
	 */
	public void setTransactionStatus(String value) {
		setValue(19, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.transaction_status</code>.
	 */
	public String getTransactionStatus() {
		return (String) getValue(19);
	}

	/**
	 * Setter for <code>authorize_net_transactions.transaction_message</code>.
	 */
	public void setTransactionMessage(String value) {
		setValue(20, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.transaction_message</code>.
	 */
	public String getTransactionMessage() {
		return (String) getValue(20);
	}

	/**
	 * Setter for <code>authorize_net_transactions.transaction_error</code>.
	 */
	public void setTransactionError(String value) {
		setValue(21, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.transaction_error</code>.
	 */
	public String getTransactionError() {
		return (String) getValue(21);
	}

	/**
	 * Setter for <code>authorize_net_transactions.test_request</code>.
	 */
	public void setTestRequest(String value) {
		setValue(22, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.test_request</code>.
	 */
	public String getTestRequest() {
		return (String) getValue(22);
	}

	/**
	 * Setter for <code>authorize_net_transactions.success</code>.
	 */
	public void setSuccess(Byte value) {
		setValue(23, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.success</code>.
	 */
	public Byte getSuccess() {
		return (Byte) getValue(23);
	}

	/**
	 * Setter for <code>authorize_net_transactions.created_at</code>.
	 */
	public void setCreatedAt(Timestamp value) {
		setValue(24, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.created_at</code>.
	 */
	public Timestamp getCreatedAt() {
		return (Timestamp) getValue(24);
	}

	/**
	 * Setter for <code>authorize_net_transactions.updated_at</code>.
	 */
	public void setUpdatedAt(Timestamp value) {
		setValue(25, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.updated_at</code>.
	 */
	public Timestamp getUpdatedAt() {
		return (Timestamp) getValue(25);
	}

	/**
	 * Setter for <code>authorize_net_transactions.kb_account_id</code>.
	 */
	public void setKbAccountId(String value) {
		setValue(26, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.kb_account_id</code>.
	 */
	public String getKbAccountId() {
		return (String) getValue(26);
	}

	/**
	 * Setter for <code>authorize_net_transactions.kb_tenant_id</code>.
	 */
	public void setKbTenantId(String value) {
		setValue(27, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.kb_tenant_id</code>.
	 */
	public String getKbTenantId() {
		return (String) getValue(27);
	}

	/**
	 * Setter for <code>authorize_net_transactions.kb_payment_plugin_status</code>.
	 */
	public void setKbPaymentPluginStatus(String value) {
		setValue(28, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.kb_payment_plugin_status</code>.
	 */
	public String getKbPaymentPluginStatus() {
		return (String) getValue(28);
	}

	/**
	 * Setter for <code>authorize_net_transactions.kb_ref_transaction_record_id</code>.
	 */
	public void setKbRefTransactionRecordId(ULong value) {
		setValue(29, value);
	}

	/**
	 * Getter for <code>authorize_net_transactions.kb_ref_transaction_record_id</code>.
	 */
	public ULong getKbRefTransactionRecordId() {
		return (ULong) getValue(29);
	}

	// -------------------------------------------------------------------------
	// Primary key information
	// -------------------------------------------------------------------------

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Record1<ULong> key() {
		return (Record1) super.key();
	}

	// -------------------------------------------------------------------------
	// Constructors
	// -------------------------------------------------------------------------

	/**
	 * Create a detached AuthorizeNetTransactionsRecord
	 */
	public AuthorizeNetTransactionsRecord() {
		super(AuthorizeNetTransactions.AUTHORIZE_NET_TRANSACTIONS);
	}

	/**
	 * Create a detached, initialised AuthorizeNetTransactionsRecord
	 */
	public AuthorizeNetTransactionsRecord(ULong recordId, ULong requestId, String kbPaymentId, String kbPaymentMethodId, String kbPaymentTransactionId, String kbTransactionType, String transactionType, String authorizeNetCustomerProfileId, String authorizeNetPaymentProfileId, String authorizeNetTransactionId, BigDecimal amount, String currency, String authCode, String avsResultCode, String cvvResultCode, String cavvResultCode, String accountType, String responseStatus, String responseMessage, String transactionStatus, String transactionMessage, String transactionError, String testRequest, Byte success, Timestamp createdAt, Timestamp updatedAt, String kbAccountId, String kbTenantId, String kbPaymentPluginStatus, ULong kbRefTransactionRecordId) {
		super(AuthorizeNetTransactions.AUTHORIZE_NET_TRANSACTIONS);

		setValue(0, recordId);
		setValue(1, requestId);
		setValue(2, kbPaymentId);
		setValue(3, kbPaymentMethodId);
		setValue(4, kbPaymentTransactionId);
		setValue(5, kbTransactionType);
		setValue(6, transactionType);
		setValue(7, authorizeNetCustomerProfileId);
		setValue(8, authorizeNetPaymentProfileId);
		setValue(9, authorizeNetTransactionId);
		setValue(10, amount);
		setValue(11, currency);
		setValue(12, authCode);
		setValue(13, avsResultCode);
		setValue(14, cvvResultCode);
		setValue(15, cavvResultCode);
		setValue(16, accountType);
		setValue(17, responseStatus);
		setValue(18, responseMessage);
		setValue(19, transactionStatus);
		setValue(20, transactionMessage);
		setValue(21, transactionError);
		setValue(22, testRequest);
		setValue(23, success);
		setValue(24, createdAt);
		setValue(25, updatedAt);
		setValue(26, kbAccountId);
		setValue(27, kbTenantId);
		setValue(28, kbPaymentPluginStatus);
		setValue(29, kbRefTransactionRecordId);
	}
}