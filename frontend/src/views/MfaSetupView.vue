<script setup lang="ts">
import { ref } from 'vue'
import { api, messageFor } from '../api/http'
import { useAuth } from '../stores/auth'

const auth = useAuth()
const password = ref('')
const code = ref('')
const secret = ref('')
const recovery = ref<string[]>([])
const error = ref('')

async function start() {
  error.value = ''
  try {
    const r = await api<{ secret: string; otpauthUri: string }>('/api/v1/auth/mfa/setup', {
      method: 'POST',
      body: { currentPassword: password.value },
    })
    secret.value = r.secret
    password.value = ''
  } catch (e) {
    error.value = messageFor(e)
  }
}
async function confirm() {
  error.value = ''
  try {
    const r = await api<{ recoveryCodes: string[] }>('/api/v1/auth/mfa/confirm', { method: 'POST', body: { code: code.value.trim() } })
    recovery.value = r.recoveryCodes
    await auth.load()
  } catch (e) {
    error.value = messageFor(e)
  }
}
</script>

<template>
  <h1>Activar verificación en dos pasos</h1>
  <template v-if="recovery.length">
    <p><strong>Guarde estos códigos de recuperación en un lugar seguro. Se muestran una sola vez y cada uno sirve una vez.</strong></p>
    <ul><li v-for="c in recovery" :key="c"><code>{{ c }}</code></li></ul>
    <RouterLink to="/">Continuar</RouterLink>
  </template>
  <form v-else-if="!secret" @submit.prevent="start">
    <label for="pw">Confirme su contraseña actual</label>
    <input id="pw" v-model="password" type="password" autocomplete="current-password" required />
    <button type="submit">Continuar</button>
  </form>
  <form v-else @submit.prevent="confirm">
    <p>Agregue esta clave en su app autenticadora:</p>
    <p><code>{{ secret }}</code></p>
    <!-- Mejora sugerida por proyecto: mostrar un QR generado localmente (sin servicios externos) a partir de otpauthUri. -->
    <label for="code">Código de 6 dígitos</label>
    <input id="code" v-model="code" inputmode="numeric" autocomplete="one-time-code" required maxlength="6" />
    <button type="submit">Activar</button>
  </form>
  <p v-if="error" class="error" role="alert">{{ error }}</p>
</template>
