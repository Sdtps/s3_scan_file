import boto3
import json
import sys
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor

class S3PublicAuditor:
    def __init__(self):
        # Utiliza a sessão configurada no AWS CLI (aws configure)
        try:
            self.s3_client = boto3.client('s3')
            self.s3_resource = boto3.resource('s3')
        except Exception as e:
            print(f"❌ Erro ao inicializar sessão AWS: {e}")
            sys.exit(1)

    def is_bucket_policy_public(self, bucket_name):
        """Verifica se a Bucket Policy permite acesso público (Principal: *)"""
        try:
            policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_json = json.loads(policy['Policy'])
            
            for statement in policy_json.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    principal = statement.get('Principal')
                    # Verifica Principal "*" ou {"AWS": "*"}
                    if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                        return True
            return False
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                return False
            print(f"⚠️ Erro ao ler policy do bucket {bucket_name}: {e}")
            return False

    def check_object_exposure(self, bucket_name, bucket_is_public_by_policy):
        """Varre objetos do bucket identificando exposição via ACL ou Policy"""
        exposed_objects = []
        paginator = self.s3_client.get_paginator('list_objects_v2')
        
        try:
            # Paginação para lidar com buckets grandes
            page_iterator = paginator.paginate(Bucket=bucket_name)
            
            has_objects = False
            for page in page_iterator:
                if 'Contents' not in page:
                    continue
                
                has_objects = True
                for obj in page['Contents']:
                    obj_key = obj['Key']
                    reasons = []

                    # 1. Checagem via Policy (Herdada do bucket)
                    if bucket_is_public_by_policy:
                        reasons.append("Bucket Policy")

                    # 2. Checagem via ACL do Objeto
                    try:
                        acl = self.s3_client.get_object_acl(Bucket=bucket_name, Key=obj_key)
                        for grant in acl.get('Grants', []):
                            grantee = grant.get('Grantee', {})
                            # URI do grupo AllUsers (Acesso Público)
                            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                                permission = grant.get('Permission')
                                if permission in ['READ', 'FULL_CONTROL']:
                                    reasons.append(f"Object ACL ({permission})")
                    except ClientError:
                        pass # Erro ao ler ACL específica do objeto

                    if reasons:
                        result = {
                            "bucket": bucket_name,
                            "object": obj_key,
                            "exposure_type": " & ".join(reasons)
                        }
                        exposed_objects.append(result)
                        print(f"🚨 EXPOSTO: {bucket_name} | Objeto: {obj_key} | Via: {result['exposure_type']}")

            if not has_objects:
                print(f"ℹ️ Bucket '{bucket_name}' está vazio.")

        except ClientError as e:
            print(f"❌ Erro ao listar objetos em {bucket_name}: {e}")

        return exposed_objects

    def audit_bucket(self, bucket_name):
        """Função worker para processamento paralelo"""
        print(f"🔍 Auditando bucket: {bucket_name}")
        is_public_policy = self.is_bucket_policy_public(bucket_name)
        return self.check_object_exposure(bucket_name, is_public_policy)

    def run(self):
        """Executa o fluxo principal de auditoria"""
        try:
            response = self.s3_client.list_buckets()
            buckets = [b['Name'] for b in response.get('Buckets', [])]
        except ClientError as e:
            print(f"❌ Erro fatal ao listar buckets: {e}")
            return

        if not buckets:
            print("ℹ️ Nenhum bucket encontrado na conta.")
            return

        print(f"🚀 Iniciando auditoria em {len(buckets)} buckets...")
        
        all_exposed = []
        
        # Uso de concorrência para melhorar performance em contas com muitos buckets
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(self.audit_bucket, buckets))
            
        for result_list in results:
            all_exposed.extend(result_list)

        # Preparação para exportação JSON
        if all_exposed:
            self.export_results(all_exposed)
        else:
            print("\n✅ Auditoria finalizada. Nenhum objeto público encontrado.")

    def export_results(self, data):
        filename = "s3_audit_report.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"\n📄 Relatório detalhado exportado para: {filename}")

if __name__ == "__main__":
    auditor = S3PublicAuditor()
    auditor.run()