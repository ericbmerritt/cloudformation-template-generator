package com.monsanto.arch.cloudformation.model.resource

import com.monsanto.arch.cloudformation.model.{ConditionRef, Token}
import spray.json.DefaultJsonProtocol._
import spray.json.{
  DefaultJsonProtocol,
  JsObject,
  JsString,
  JsValue,
  JsonFormat
}

case class CognitoIdentityProvider(
    ClientId: Option[String] = None,
    ProviderName: Option[String] = None,
    ServerSideTokenCheck: Option[Boolean] = None)

object CognitoIdentityProvider {
  implicit val format: JsonFormat[CognitoIdentityProvider] = jsonFormat3(
    CognitoIdentityProvider.apply)
}

sealed trait StreamingStatus
object StreamingStatus extends DefaultJsonProtocol {
  case object ENABLED extends StreamingStatus
  case object DISABLED extends StreamingStatus

  implicit val format: JsonFormat[StreamingStatus] =
    new JsonFormat[StreamingStatus] {
      override def write(obj: StreamingStatus): JsValue = obj match {
        case ENABLED => JsString("ENABLED")
        case DISABLED => JsString("DISABLED")
      }
      override def read(json: JsValue): StreamingStatus = {
        json.toString match {
          case "ENABLED" => ENABLED
          case "DISABLED" => DISABLED
        }
      }
    }
}
case class CognitoStreams(RoleArn: Option[Token[String]],
                          StreamingStatus: StreamingStatus,
                          StreamName: String)

object CognitoStreams {
  implicit val format: JsonFormat[CognitoStreams] = jsonFormat3(
    CognitoStreams.apply)
}

case class PushSync(
    ApplicationArns: Seq[Token[String]],
    RoleArn: Token[String]
)
object PushSync {
  implicit val format: JsonFormat[PushSync] = jsonFormat2(PushSync.apply)
}

case class `AWS::Cognito::IdentityPool`(
    name: String,
    IdentityPoolName: Option[String] = None,
    AllowUnauthenticatedIdentities: Boolean,
    DeveloperProviderName: Option[String] = None,
    SupportedLoginProviders: Option[Map[String, String]] = None,
    SamlProviderARNs: Option[Seq[Token[String]]] = None,
    OpenIdConnectProviderARNs: Option[Seq[Token[String]]] = None,
    CognitoStreams: Option[CognitoStreams] = None,
    PushSync: Option[PushSync] = None,
    CognitoEvents: Option[Map[String, String]] = None,
    override val Condition: Option[ConditionRef] = None
) extends Resource[`AWS::Cognito::IdentityPool`] {
  override def when(newCondition: Option[ConditionRef]) =
    copy(Condition = newCondition)
}
object `AWS::Cognito::IdentityPool` {
  implicit val format: JsonFormat[`AWS::Cognito::IdentityPool`] =
    jsonFormat11(`AWS::Cognito::IdentityPool`.apply)
}

sealed trait AmbiguousRoleResolution
object AmbiguousRoleResolution extends DefaultJsonProtocol {
  case object AuthenticatedRole extends AmbiguousRoleResolution
  case object Deny extends AmbiguousRoleResolution

  implicit val format: JsonFormat[AmbiguousRoleResolution] =
    new JsonFormat[AmbiguousRoleResolution] {
      override def write(obj: AmbiguousRoleResolution): JsValue = obj match {
        case AuthenticatedRole => JsString("AuthenticatedRole")
        case Deny => JsString("Deny")
      }
      override def read(json: JsValue): AmbiguousRoleResolution = {
        json.toString match {
          case "AmbiguousRoleResolution" => AuthenticatedRole
          case "Deny" => Deny
        }
      }
    }
}

sealed trait MatchType
object MatchType extends DefaultJsonProtocol {
  case object Contains extends MatchType
  case object Equals extends MatchType
  case object NotEqual extends MatchType
  case object StartsWith extends MatchType

  implicit val format: JsonFormat[MatchType] =
    new JsonFormat[MatchType] {
      override def write(obj: MatchType): JsValue = obj match {
        case Contains => JsString("Contains")
        case Equals => JsString("Equals")
        case NotEqual => JsString("NotEqual")
        case StartsWith => JsString("StartsWith")
      }
      override def read(json: JsValue): MatchType = {
        json.toString match {
          case "Contains" => Contains
          case "Equals" => Equals
          case "NotEqual" => NotEqual
          case "StartsWith" => StartsWith
        }
      }
    }
}

case class MappingRule(Claim: String,
                       matchType: MatchType,
                       RoleARN: Token[String],
                       Value: String)
object MappingRule {
  implicit val format: JsonFormat[MappingRule] = jsonFormat4(MappingRule.apply)
}

case class RulesConfiguration(Rules: Seq[MappingRule])
object RulesConfiguration {
  implicit val format: JsonFormat[RulesConfiguration] = jsonFormat1(
    RulesConfiguration.apply)
}
sealed trait Type
object Type extends DefaultJsonProtocol {
  case object Token extends Type
  case object Rules extends Type

  implicit val format: JsonFormat[Type] =
    new JsonFormat[Type] {
      override def write(obj: Type): JsValue = obj match {
        case Token => JsString("Token")
        case Rules => JsString("Rules")
      }
      override def read(json: JsValue): Type = {
        json.toString match {
          case "Token" => Token
          case "Rules" => Rules
        }
      }
    }
}
case class RoleMapping(
    AmbiguousRoleResolution: Option[AmbiguousRoleResolution] = None,
    RulesConfiguration: Option[RulesConfiguration] = None,
    Type: Type
)
object RoleMapping {
  implicit val format: JsonFormat[RoleMapping] = jsonFormat3(RoleMapping.apply)
}

case class `AWS::Cognito::IdentityPoolRoleAttachment`(
    name: String,
    IdentityPoolId: Token[String],
    RoleMappings: Option[Map[String, RoleMapping]] = None,
    Roles: Option[Map[String, String]],
    override val Condition: Option[ConditionRef] = None
) extends Resource[`AWS::Cognito::IdentityPoolRoleAttachment`] {
  override def when(newCondition: Option[ConditionRef]) =
    copy(Condition = newCondition)
}
object `AWS::Cognito::IdentityPoolRoleAttachment` {
  implicit val format: JsonFormat[`AWS::Cognito::IdentityPoolRoleAttachment`] =
    jsonFormat5(`AWS::Cognito::IdentityPoolRoleAttachment`.apply)
}

case class InviteMessageTemplate(EmailMessage: String,
                                 EmailSubject: String,
                                 SMSMessage: String)
object InviteMessageTemplate {
  implicit val format: JsonFormat[InviteMessageTemplate] = jsonFormat3(
    InviteMessageTemplate.apply)
}

case class AdminCreateUserConfig(AllowAdminCreateUserOnly: Boolean,
                                 InviteMessageTemplate: InviteMessageTemplate,
                                 UnusedAccountValidityDays: Int)
object AdminCreateUserConfig {
  implicit val format: JsonFormat[AdminCreateUserConfig] = jsonFormat3(
    AdminCreateUserConfig.apply)
}

sealed trait AliasAttribute
object AliasAttribute extends DefaultJsonProtocol {
  case object PhoneNumber extends AliasAttribute
  case object Email extends AliasAttribute
  case object PreferredUsername extends AliasAttribute

  implicit val format: JsonFormat[AliasAttribute] =
    new JsonFormat[AliasAttribute] {
      override def write(obj: AliasAttribute): JsValue = obj match {
        case PhoneNumber => JsString("phone_number")
        case Email => JsString("email")
        case PreferredUsername => JsString("preferred_username")
      }
      override def read(json: JsValue): AliasAttribute = {
        json.toString match {
          case "phone_number" => PhoneNumber
          case "email" => Email
          case "preferred_username" => PreferredUsername
        }
      }
    }
}

sealed trait AutoVerifiedAttribute
object AutoVerifiedAttribute extends DefaultJsonProtocol {
  case object PhoneNumber extends AutoVerifiedAttribute
  case object Email extends AutoVerifiedAttribute

  implicit val format: JsonFormat[AutoVerifiedAttribute] =
    new JsonFormat[AutoVerifiedAttribute] {
      override def write(obj: AutoVerifiedAttribute): JsValue = obj match {
        case PhoneNumber => JsString("phone_number")
        case Email => JsString("email")
      }
      override def read(json: JsValue): AutoVerifiedAttribute = {
        json.toString match {
          case "phone_number" => PhoneNumber
          case "email" => Email
        }
      }
    }
}

case class DeviceConfiguration(ChallengeRequiredOnNewDevice: Boolean,
                               DeviceOnlyRememberedOnUserPrompt: Boolean)
object DeviceConfiguration {
  implicit val format: JsonFormat[DeviceConfiguration] = jsonFormat2(
    DeviceConfiguration.apply)
}

case class EmailConfiguration(
    ReplyToEmailAddress: String,
    SourceArn: Token[String]
)
object EmailConfiguration {
  implicit val format: JsonFormat[EmailConfiguration] = jsonFormat2(
    EmailConfiguration.apply)
}

case class LambdaConfig(
    CreateAuthChallenge: Option[Token[String]] = None,
    CustomMessage: Option[Token[String]] = None,
    DefineAuthChallenge: Option[Token[String]] = None,
    PostAuthentication: Option[Token[String]] = None,
    PostConfirmation: Option[Token[String]] = None,
    PreAuthentication: Option[Token[String]] = None,
    PreSignUp: Option[Token[String]] = None,
    VerifyAuthChallengeResponse: Option[Token[String]] = None
)
object LambdaConfig {
  implicit val format: JsonFormat[LambdaConfig] = jsonFormat8(
    LambdaConfig.apply)
}

sealed trait MfaConfiguration
object MfaConfiguration extends DefaultJsonProtocol {
  case object ON extends MfaConfiguration
  case object OFF extends MfaConfiguration
  case object OPTIONAL extends MfaConfiguration

  implicit val format: JsonFormat[MfaConfiguration] =
    new JsonFormat[MfaConfiguration] {
      override def write(obj: MfaConfiguration): JsValue = obj match {
        case ON => JsString("ON")
        case OFF => JsString("OFF")
        case OPTIONAL => JsString("OPTIONAL")
      }
      override def read(json: JsValue): MfaConfiguration = {
        json.toString match {
          case "ON" => ON
          case "OFF" => OFF
          case "OPTIONAL" => OPTIONAL
        }
      }
    }
}

case class PasswordPolicy(
    MinimumLength: Int,
    RequireLowercase: Boolean,
    RequireNumbers: Boolean,
    RequireSymbols: Boolean,
    RequireUppercase: Boolean
)
object PasswordPolicy {
  implicit val format: JsonFormat[PasswordPolicy] = jsonFormat5(
    PasswordPolicy.apply)
}
case class Policies(PasswordPolicy: PasswordPolicy)
object Policies {
  implicit val format: JsonFormat[Policies] = jsonFormat1(Policies.apply)
}

case class AttributeConstraints(MaxLength: Int, MinLength: Int)
object AttributeConstraints {
  implicit val format: JsonFormat[AttributeConstraints] =
    new JsonFormat[AttributeConstraints] {
      override def write(obj: AttributeConstraints): JsValue =
        JsObject("MaxLength" -> JsString(obj.MaxLength.toString),
                 "MinLength" -> JsString(obj.MinLength.toString))

      override def read(json: JsValue): AttributeConstraints = {
        json match {
          case obj: JsObject =>
            val maxLength = obj.fields("MaxLength").toString().toInt
            val minLength = obj.fields("MinLength").toString().toInt
            AttributeConstraints(MaxLength = maxLength, MinLength = minLength)
          case _ =>
            throw new RuntimeException(
              s"Got value which is not an AttributeConstraint $json")
        }
      }
    }
}

case class SchemaAttribute(
    AttributeDataType: String,
    DeveloperOnlyAttribute: Boolean,
    Mutable: Boolean,
    Name: String,
    NumberAttributeConstraints: AttributeConstraints,
    StringAttributeConstraints: AttributeConstraints,
    Required: Boolean
)
object SchemaAttribute {
  implicit val format: JsonFormat[SchemaAttribute] = jsonFormat7(
    SchemaAttribute.apply)
}

case class SmsConfiguration(
    ExternalId: String,
    SnsCallerArn: Token[String]
)
object SmsConfiguration {
  implicit val format: JsonFormat[SmsConfiguration] = jsonFormat2(
    SmsConfiguration.apply)
}

case class `AWS::Cognito::UserPool`(
    name: String,
    AdminCreateUserConfig: Option[AdminCreateUserConfig] = None,
    AliasAttribute: Option[Seq[AliasAttribute]] = None,
    AutoVerifiedAttribute: Option[Seq[AutoVerifiedAttribute]] = None,
    DeviceConfiguration: Option[DeviceConfiguration] = None,
    EmailConfiguration: Option[EmailConfiguration] = None,
    EmailVerificationMessage: Option[String] = None,
    EmailVerificationSubject: Option[String] = None,
    LambdaConfig: Option[LambdaConfig] = None,
    MfaConfiguration: Option[MfaConfiguration] = None,
    Policies: Option[Policies] = None,
    UserPoolName: String,
    Schema: Option[Seq[SchemaAttribute]] = None,
    SmsAuthenticationMessage: Option[String] = None,
    SmsConfiguration: Option[SmsConfiguration] = None,
    SmsVerificationMessage: Option[String] = None,
    UserPoolTags: Option[Map[String, String]] = None,
    override val Condition: Option[ConditionRef] = None
) extends Resource[`AWS::Cognito::UserPool`] {
  override def when(newCondition: Option[ConditionRef]) =
    copy(Condition = newCondition)
}
object `AWS::Cognito::UserPool` {
  implicit val format: JsonFormat[`AWS::Cognito::UserPool`] =
    jsonFormat18(`AWS::Cognito::UserPool`.apply)
}

sealed trait ExplicitAuthFlows
object ExplicitAuthFlows extends DefaultJsonProtocol {
  case object ADMIN_NO_SRP_AUTH extends ExplicitAuthFlows
  case object CUSTOM_AUTH_FLOW_ONLY extends ExplicitAuthFlows

  implicit val format: JsonFormat[ExplicitAuthFlows] =
    new JsonFormat[ExplicitAuthFlows] {
      override def write(obj: ExplicitAuthFlows): JsValue = obj match {
        case ADMIN_NO_SRP_AUTH => JsString("ADMIN_NO_SRP_AUTH")
        case CUSTOM_AUTH_FLOW_ONLY => JsString("CUSTOM_AUTH_FLOW_ONLY")
      }
      override def read(json: JsValue): ExplicitAuthFlows = {
        json.toString match {
          case "ADMIN_NO_SRP_AUTH" => ADMIN_NO_SRP_AUTH
          case "CUSTOM_AUTH_FLOW_ONLY" => CUSTOM_AUTH_FLOW_ONLY
        }
      }
    }
}

case class `AWS::Cognito::UserPoolClient`(
    name: String,
    ClientName: Option[String] = None,
    ExplicitAuthFlows: Option[Seq[ExplicitAuthFlows]] = None,
    GenerateSecret: Option[Boolean] = None,
    ReadAttributes: Option[Seq[String]] = None,
    RefreshTokenValidity: Option[Int] = None,
    UserPoolId: Token[String],
    WriteAttributes: Option[Seq[String]] = None,
    override val Condition: Option[ConditionRef] = None
) extends Resource[`AWS::Cognito::UserPoolClient`] {
  override def when(newCondition: Option[ConditionRef]) =
    copy(Condition = newCondition)
}
object `AWS::Cognito::UserPoolClient` {
  implicit val format: JsonFormat[`AWS::Cognito::UserPoolClient`] =
    jsonFormat9(`AWS::Cognito::UserPoolClient`.apply)
}

case class `AWS::Cognito::UserPoolGroup`(
    name: String,
    Description: Option[String] = None,
    GroupName: String,
    Precedence: Option[Int] = None,
    RoleArn: Option[Token[String]] = None,
    UserPoolId: Token[String],
    override val Condition: Option[ConditionRef] = None
) extends Resource[`AWS::Cognito::UserPoolGroup`] {
  override def when(newCondition: Option[ConditionRef]) =
    copy(Condition = newCondition)
}
object `AWS::Cognito::UserPoolGroup` {
  implicit val format: JsonFormat[`AWS::Cognito::UserPoolGroup`] =
    jsonFormat7(`AWS::Cognito::UserPoolGroup`.apply)
}

sealed trait DesiredDeliveryMediums
object DesiredDeliveryMediums extends DefaultJsonProtocol {
  case object EMAIL extends DesiredDeliveryMediums
  case object SMS extends DesiredDeliveryMediums

  implicit val format: JsonFormat[DesiredDeliveryMediums] =
    new JsonFormat[DesiredDeliveryMediums] {
      override def write(obj: DesiredDeliveryMediums): JsValue = obj match {
        case EMAIL => JsString("EMAIL")
        case SMS => JsString("SMS")
      }
      override def read(json: JsValue): DesiredDeliveryMediums = {
        json.toString match {
          case "SMS" => SMS
          case "EMAIL" => EMAIL
        }
      }
    }
}
case class CognitoAttributeType(Name: String, Value: String)
object CognitoAttributeType {
  implicit val format: JsonFormat[CognitoAttributeType] =
    jsonFormat2(CognitoAttributeType.apply)
}

sealed trait MessageAction
object MessageAction extends DefaultJsonProtocol {
  case object RESEND extends MessageAction
  case object SUPPRESS extends MessageAction

  implicit val format: JsonFormat[MessageAction] =
    new JsonFormat[MessageAction] {
      override def write(obj: MessageAction): JsValue = obj match {
        case RESEND => JsString("RESEND")
        case SUPPRESS => JsString("SUPPRESS")
      }
      override def read(json: JsValue): MessageAction = {
        json.toString match {
          case "RESEND" => RESEND
          case "SUPPRESS" => SUPPRESS
        }
      }
    }
}
case class `AWS::Cognito::UserPoolUser`(
    name: String,
    DesiredDeliveryMediums: Option[DesiredDeliveryMediums] = None,
    ForceAliasCreation: Option[Boolean] = None,
    UserAttributes: Option[Seq[CognitoAttributeType]] = None,
    MessageAction: Option[MessageAction] = None,
    Username: Option[String] = None,
    UserPoolId: Token[String],
    ValidationData: Option[Seq[CognitoAttributeType]] = None,
    override val Condition: Option[ConditionRef] = None
) extends Resource[`AWS::Cognito::UserPoolUser`] {
  override def when(newCondition: Option[ConditionRef]) =
    copy(Condition = newCondition)
}
object `AWS::Cognito::UserPoolUser` {
  implicit val format: JsonFormat[`AWS::Cognito::UserPoolUser`] =
    jsonFormat9(`AWS::Cognito::UserPoolUser`.apply)
}

case class `AWS::Cognito::UserPoolUserToGroupAttachment`(
    name: String,
    GroupName: String,
    Username: String,
    UserPoolId: Token[String],
    override val Condition: Option[ConditionRef] = None
) extends Resource[`AWS::Cognito::UserPoolUserToGroupAttachment`] {
  override def when(newCondition: Option[ConditionRef]) =
    copy(Condition = newCondition)
}
object `AWS::Cognito::UserPoolUserToGroupAttachment` {
  implicit val format
    : JsonFormat[`AWS::Cognito::UserPoolUserToGroupAttachment`] =
    jsonFormat5(`AWS::Cognito::UserPoolUserToGroupAttachment`.apply)
}
